// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package accounts implements encrypted storage of secp256k1 private keys.
//
// Keys are stored as encrypted JSON files according to the Web3 Secret Storage specification.
// See https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition for more information.
package accounts

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"encoding/json"
	"path/filepath"

	"github.com/kar98kar/go-ulogos/common"
	"github.com/kar98kar/go-ulogos/crypto"
)

var (
	ErrLocked  = errors.New("account is locked")
	ErrNoMatch = errors.New("no key for given address or file")
	ErrDecrypt = errors.New("could not decrypt key with given passphrase")

	errAddrMismatch = errors.New("security violation: address of file didn't match request")
)

// Account represents a stored key.
// When used as an argument, it selects a unique key file to act on.
type Account struct {
	Address      common.Address // Ethereum account address derived from the key
	EncryptedKey string         // web3JSON format

	// File contains the key file name.
	// When Acccount is used as an argument to select a key, File can be left blank to
	// select just by address or set to the basename or absolute path of a file in the key
	// directory. Accounts returned by Manager will always contain an absolute path.
	File string
}

// AccountJSON is an auxiliary between Account and EasyMarshal'd structs.
//easyjson:json
type AccountJSON struct {
	Address      string `json:"address"`
	EncryptedKey string `json:"key"`
	File         string `json:"file"`
}

func (acc *Account) MarshalJSON() ([]byte, error) {
	return []byte(`"` + acc.Address.Hex() + `"`), nil
}

func (acc *Account) UnmarshalJSON(raw []byte) error {
	return json.Unmarshal(raw, &acc.Address)
}

// Manager manages a key storage directory on disk.
type Manager struct {
	ac       caching
	keyStore keyStore
	mu       sync.RWMutex
	unlocked map[common.Address]*unlocked
}

type unlocked struct {
	*key
	abort chan struct{}
}

const (
	// n,r,p = 2^18, 8, 1 uses 256MB memory and approx 1s CPU time on a modern CPU.
	StandardScryptN = 1 << 18
	StandardScryptP = 1

	// n,r,p = 2^12, 8, 6 uses 4MB memory and approx 100ms CPU time on a modern CPU.
	LightScryptN = 1 << 12
	LightScryptP = 6

	scryptR     = 8
	scryptDKLen = 32
)

// NewManager creates a manager for the given directory.
// keydir is by default /Users/ia/Library/EthereumClassic/mainnet/keystore
func NewManager(keydir string, scryptN, scryptP int, wantCacheDB bool) (*Manager, error) {
	store, err := newKeyStore(keydir, scryptN, scryptP)
	if err != nil {
		return nil, err
	}

	am := &Manager{
		keyStore: *store,
		unlocked: make(map[common.Address]*unlocked),
	}
	if wantCacheDB {
		am.ac = newCacheDB(keydir)
	} else {
		am.ac = newAddrCache(keydir)
	}

	// TODO: In order for this finalizer to work, there must be no references
	// to am. addrCache doesn't keep a reference but unlocked keys do,
	// so the finalizer will not trigger until all timed unlocks have expired.
	runtime.SetFinalizer(am, func(m *Manager) {
		// bug(whilei): I was getting panic: close of closed channel when running tests as package;
		// individually each test would pass but not when run in a bunch.
		// either manager reference was stuck somewhere or the tests were outpacing themselves
		// checking for nil seems to fix the issue.
		if am.ac != nil {
			m.ac.close()
		}

	})

	return am, nil
}

func (am *Manager) BuildIndexDB() []error {
	return am.ac.Syncfs2db(time.Now().Add(-60 * 24 * 7 * 30 * 120 * time.Minute)) // arbitrarily long "last updated"
}

// HasAddress reports whether a key with the given address is present.
func (am *Manager) HasAddress(addr common.Address) bool {
	return am.ac.hasAddress(addr)
}

// Accounts returns all key files present in the directory.
func (am *Manager) Accounts() []Account {
	return am.ac.accounts()
}

// DeleteAccount deletes the key matched by account if the passphrase is correct.
// If a contains no filename, the address must match a unique key.
func (am *Manager) DeleteAccount(a Account, passphrase string) error {
	// Decrypting the key isn't really necessary, but we do
	// it anyway to check the password and zero out the key
	// immediately afterwards.
	a, key, err := am.getDecryptedKey(a, passphrase)
	if key != nil {
		zeroKey(key.PrivateKey)
	}
	if err != nil {
		return err
	}

	if !filepath.IsAbs(a.File) {
		p := filepath.Join(am.ac.getKeydir(), a.File)
		a.File = p
	}

	// The order is crucial here. The key is dropped from the
	// cache after the file is gone so that a reload happening in
	// between won't insert it into the cache again.
	err = os.Remove(a.File)
	if err == nil {
		am.ac.delete(a)
	}
	return err
}

// Sign signs hash with an unlocked private key matching the given address.
func (am *Manager) Sign(addr common.Address, hash []byte) (signature []byte, err error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	unlockedKey, found := am.unlocked[addr]
	if !found {
		return nil, ErrLocked
	}
	return crypto.Sign(hash, unlockedKey.PrivateKey)
}

// SignWithPassphrase signs hash if the private key matching the given address can be
// decrypted with the given passphrase.
func (am *Manager) SignWithPassphrase(addr common.Address, passphrase string, hash []byte) (signature []byte, err error) {
	_, key, err := am.getDecryptedKey(Account{Address: addr}, passphrase)
	if err != nil {
		return nil, err
	}

	defer zeroKey(key.PrivateKey)
	return crypto.Sign(hash, key.PrivateKey)
}

// Unlock unlocks the given account indefinitely.
func (am *Manager) Unlock(a Account, passphrase string) error {
	return am.TimedUnlock(a, passphrase, 0)
}

// Lock removes the private key with the given address from memory.
func (am *Manager) Lock(addr common.Address) error {
	am.mu.Lock()
	if unl, found := am.unlocked[addr]; found {
		am.mu.Unlock()
		am.expire(addr, unl, time.Duration(0)*time.Nanosecond)
	} else {
		am.mu.Unlock()
	}
	return nil
}

// TimedUnlock unlocks the given account with the passphrase. The account
// stays unlocked for the duration of timeout. A timeout of 0 unlocks the account
// until the program exits. The account must match a unique key file.
//
// If the account address is already unlocked for a duration, TimedUnlock extends or
// shortens the active unlock timeout. If the address was previously unlocked
// indefinitely the timeout is not altered.
func (am *Manager) TimedUnlock(a Account, passphrase string, timeout time.Duration) error {
	a, key, err := am.getDecryptedKey(a, passphrase)
	if err != nil {
		return err
	}

	am.mu.Lock()
	defer am.mu.Unlock()
	u, found := am.unlocked[a.Address]
	if found {
		if u.abort == nil {
			// The address was unlocked indefinitely, so unlocking
			// it with a timeout would be confusing.
			zeroKey(key.PrivateKey)
			return nil
		} else {
			// Terminate the expire goroutine and replace it below.
			close(u.abort)
		}
	}
	if timeout > 0 {
		u = &unlocked{key: key, abort: make(chan struct{})}
		go am.expire(a.Address, u, timeout)
	} else {
		u = &unlocked{key: key}
	}
	am.unlocked[a.Address] = u
	return nil
}

func (am *Manager) getDecryptedKey(a Account, auth string) (Account, *key, error) {
	am.ac.maybeReload()
	am.ac.muLock()
	a, err := am.ac.find(a)
	am.ac.muUnlock()
	if err != nil {
		return Account{}, nil, err
	}

	key := &key{}
	if a.EncryptedKey != "" {
		key, err = am.keyStore.DecryptKey([]byte(a.EncryptedKey), auth, a.Address[0])
	} else {
		key, err = am.keyStore.Lookup(a.File, auth, a.Address[0])
	}

	if err != nil {
		return Account{}, nil, err
	}
	if key.Address != a.Address {
		return Account{}, nil, errAddrMismatch
	}

	return a, key, err
}

func (am *Manager) expire(addr common.Address, u *unlocked, timeout time.Duration) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-u.abort:
		// just quit
	case <-t.C:
		am.mu.Lock()
		// only drop if it's still the same key instance that dropLater
		// was launched with. we can check that using pointer equality
		// because the map stores a new pointer every time the key is
		// unlocked.
		if am.unlocked[addr] == u {
			zeroKey(u.PrivateKey)
			delete(am.unlocked, addr)
		}
		am.mu.Unlock()
	}
}

// NewAccount generates a new key and stores it into the key directory,
// encrypting it with the passphrase.
func (am *Manager) NewAccount(passphrase string) (Account, error) {
	_, account, err := storeNewKey(&am.keyStore, passphrase)
	if err != nil {
		return Account{}, err
	}
	// Add the account to the cache immediately rather
	// than waiting for file system notifications to pick it up.
	am.ac.add(account)
	return account, nil
}

// AccountByIndex returns the ith account.
func (am *Manager) AccountByIndex(i int) (Account, error) {
	accounts := am.Accounts()
	if i < 0 || i >= len(accounts) {
		return Account{}, fmt.Errorf("account index %d out of range [0, %d]", i, len(accounts)-1)
	}
	return accounts[i], nil
}

// Export exports as a JSON key, encrypted with newPassphrase.
func (am *Manager) Export(a Account, passphrase, newPassphrase string) (keyJSON []byte, err error) {
	_, key, err := am.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	return encryptKey(key, newPassphrase, am.keyStore.scryptN, am.keyStore.scryptP)
}

// Import stores the given encrypted JSON key into the key directory.
func (am *Manager) Import(keyJSON []byte, passphrase, newPassphrase string) (Account, error) {
	key, err := decryptKey(keyJSON, passphrase, 0x21) // dummy prefix
	if key != nil && key.PrivateKey != nil {
		defer zeroKey(key.PrivateKey)
	}
	if err != nil {
		return Account{}, err
	}
	return am.importKey(key, newPassphrase)
}

// ImportECDSA stores the given key into the key directory, encrypting it with the passphrase.
func (am *Manager) ImportECDSA(priv *ecdsa.PrivateKey, passphrase string) (Account, error) {
	key, err := newKeyFromECDSA(priv)
	if err != nil {
		return Account{}, err
	}

	if am.ac.hasAddress(key.Address) {
		return Account{}, fmt.Errorf("account already exists")
	}

	return am.importKey(key, passphrase)
}

// ImportECDSA stores the given key into the key directory with a prefix, encrypting it with the passphrase.
func (am *Manager) ImportECDSAPrefixed(priv *ecdsa.PrivateKey, passphrase string, pref byte) (Account, error) {
	key, err := newKeyFromECDSAPrefixed(priv, pref)
	if err != nil {
		return Account{}, err
	}

	if am.ac.hasAddress(key.Address) {
		return Account{}, fmt.Errorf("account already exists")
	}

	return am.importKey(key, passphrase)
}

func (am *Manager) importKey(key *key, passphrase string) (Account, error) {
	file, err := am.keyStore.Insert(key, passphrase)
	if err != nil {
		return Account{}, err
	}

	a := Account{File: file, Address: key.Address}
	am.ac.add(a)
	return a, nil
}

// Update changes the passphrase of an existing account.
func (am *Manager) Update(a Account, passphrase, newPassphrase string) error {
	a, key, err := am.getDecryptedKey(a, passphrase)
	if err != nil {
		return err
	}
	return am.keyStore.Update(a.File, key, newPassphrase)
}

// ImportPreSaleKey decrypts the given Ethereum presale wallet and stores
// a key file in the key directory. The key file is encrypted with the same passphrase.
func (am *Manager) ImportPreSaleKey(keyJSON []byte, passphrase string) (Account, error) {
	a, _, err := importPreSaleKey(&am.keyStore, keyJSON, passphrase)
	if err != nil {
		return a, err
	}
	am.ac.add(a)
	return a, nil
}

// zeroKey zeroes a private key in memory.
func zeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}
