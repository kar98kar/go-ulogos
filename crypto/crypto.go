// Copyright 2014 The go-ethereum Authors
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

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/kar98kar/go-ulogos/common"
	"github.com/kar98kar/go-ulogos/crypto/chainhash"
	"github.com/kar98kar/go-ulogos/crypto/ecies"
	"github.com/kar98kar/go-ulogos/crypto/secp256k1"
	"github.com/kar98kar/go-ulogos/crypto/sha3"
	"github.com/kar98kar/go-ulogos/rlp"
	"golang.org/x/crypto/ripemd160"
)

func Keccak256(data ...[]byte) []byte {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

func Keccak256Hash(data ...[]byte) (h common.Hash) {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	d.Sum(h[:0])
	return h
}

// Deprecated: For backward compatibility as other packages depend on these
func Sha3(data ...[]byte) []byte          { return Keccak256(data...) }
func Sha3Hash(data ...[]byte) common.Hash { return Keccak256Hash(data...) }

// Creates an ethereum address given the bytes and the nonce
func CreateAddress(b common.Address, nonce uint64) common.Address {
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
	return common.BytesToAddress(append([]byte{0x44}, Keccak256(data)[12:]...))
}

func Sha256(data []byte) []byte {
	hash := sha256.Sum256(data)

	return hash[:]
}

func Ripemd160(data []byte) []byte {
	ripemd := ripemd160.New()
	ripemd.Write(data)

	return ripemd.Sum(nil)
}

func Ecrecover(hash, sig []byte) ([]byte, error) {
	return secp256k1.RecoverPubkey(hash, sig)
}

// New methods using proper ecdsa keys from the stdlib
func ToECDSA(prv []byte) *ecdsa.PrivateKey {
	if len(prv) == 0 {
		return nil
	}

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = secp256k1.S256()
	priv.D = new(big.Int).SetBytes(prv)
	priv.PublicKey.X, priv.PublicKey.Y = secp256k1.S256().ScalarBaseMult(prv)
	return priv
}

func FromECDSA(prv *ecdsa.PrivateKey) []byte {
	if prv == nil {
		return nil
	}
	return prv.D.Bytes()
}

func ToECDSAPub(pub []byte) *ecdsa.PublicKey {
	if len(pub) == 0 {
		return nil
	}
	x, y := elliptic.Unmarshal(secp256k1.S256(), pub)
	return &ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}
}

func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(secp256k1.S256(), pub.X, pub.Y)
}

// HexToECDSA parses a secp256k1 private key.
func HexToECDSA(hexkey string) (*ecdsa.PrivateKey, error) {
	b, err := hex.DecodeString(hexkey)
	if err != nil {
		return nil, errors.New("invalid hex string")
	}
	if len(b) != 32 {
		return nil, errors.New("invalid length, need 256 bits")
	}
	return ToECDSA(b), nil
}

// LoadECDSA loads a secp256k1 private key from the given file.
// The key data is expected to be hex-encoded.
func LoadECDSA(in io.Reader) (*ecdsa.PrivateKey, error) {
	buf := make([]byte, 64)
	if _, err := io.ReadFull(in, buf); err != nil {
		return nil, err
	}

	key, err := hex.DecodeString(string(buf))
	if err != nil {
		return nil, err
	}

	return ToECDSA(key), nil
}

// WriteECDSAKey saves a secp256k1 private key to the given file with
// restrictive permissions. The key data is saved hex-encoded.
func WriteECDSAKey(to io.Writer, key *ecdsa.PrivateKey) (int, error) {
	k := hex.EncodeToString(FromECDSA(key))
	return to.Write([]byte(k))
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
}

func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	vint := uint32(v)
	// reject upper range of s values (ECDSA malleability)
	// see discussion in secp256k1/libsecp256k1/include/secp256k1.h
	if homestead && s.Cmp(secp256k1.HalfN) > 0 {
		return false
	}
	// Frontier: allow s to be in full N range
	if s.Cmp(secp256k1.N) >= 0 {
		return false
	}
	if r.Cmp(secp256k1.N) < 0 && (vint == 27 || vint == 28) {
		return true
	} else {
		return false
	}
}

func SigToPub(hash, sig []byte) (*ecdsa.PublicKey, error) {
	s, err := Ecrecover(hash, sig)
	if err != nil {
		return nil, err
	}

	x, y := elliptic.Unmarshal(secp256k1.S256(), s)
	return &ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}, nil
}

func Sign(hash []byte, prv *ecdsa.PrivateKey) (sig []byte, err error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}

	seckey := common.LeftPadBytes(prv.D.Bytes(), prv.Params().BitSize/8)
	defer zeroBytes(seckey)
	sig, err = secp256k1.Sign(hash, seckey)
	return
}

func Encrypt(pub *ecdsa.PublicKey, message []byte) ([]byte, error) {
	return ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic(pub), message, nil, nil)
}

func Decrypt(prv *ecdsa.PrivateKey, ct []byte) ([]byte, error) {
	key := ecies.ImportECDSA(prv)
	return key.Decrypt(rand.Reader, ct, nil, nil)
}

func PubkeyToAddress(p ecdsa.PublicKey) common.Address {
	pubBytes := FromECDSAPub(&p)
	return common.BytesToAddress(append([]byte{0x21}, Keccak256(pubBytes[1:])[12:]...))
}

// Following code are modified from https://github.com/btcsuite/btcd.

// These constants define the lengths of serialized public keys.
const (
	PubKeyBytesLenCompressed   = 33
	PubKeyBytesLenUncompressed = 65
	// PubKeyBytesLenHybrid       = 65
)

const (
	pubkeyCompressed   byte = 0x2 // y_bit + x coord
	pubkeyUncompressed byte = 0x4 // x coord + y coord
	// pubkeyHybrid       byte = 0x6 // y_bit + x coord + y coord
)

// SerializeUncompressed serializes a public key in a 65-byte uncompressed
// format.
func SerializeUncompressed(p *ecdsa.PublicKey) []byte {
	b := make([]byte, 0, PubKeyBytesLenUncompressed)
	b = append(b, pubkeyUncompressed)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

// SerializeCompressed serializes a public key in a 33-byte compressed format.
func SerializeCompressed(p *ecdsa.PublicKey) []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubkeyCompressed
	if isOdd(p.Y) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(32, b, p.X.Bytes())
}

func PubkeyToAddressPrefixed(p ecdsa.PublicKey, pref byte) common.Address {
	if pref == 0x01 {
		pubBytes := SerializeCompressed(&p)

		return common.BytesToAddress(append([]byte{0x01}, chainhash.Hash160(pubBytes)...))
	} else {
		pubBytes := SerializeUncompressed(&p)

		return common.BytesToAddress(append([]byte{0x00}, chainhash.Hash160(pubBytes)...))
	}
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

// paddedAppend appends the src byte slice to dst, returning the new slice.
// If the length of the source is smaller than the passed size, leading zero
// bytes are appended to the dst slice before appending src.
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}
