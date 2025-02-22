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

package registrar

import (
	"testing"

	"github.com/kar98kar/go-ulogos/common"
	"github.com/kar98kar/go-ulogos/crypto"
)

type testBackend struct {
	// contracts mock
	contracts map[string](map[string]string)
}

var (
	text     = "test"
	codehash = common.Hash{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '1', '2', '3', '4'}
	hash     = crypto.Sha3Hash([]byte(text))
	url      = "bzz://bzzhash/my/path/contr.act"
)

func NewTestBackend() *testBackend {
	self := &testBackend{}
	self.contracts = make(map[string](map[string]string))
	return self
}

func (self *testBackend) initHashReg() {
	self.contracts[HashRegAddr[2:]] = make(map[string]string)
	key := storageAddress(storageMapping(storageIdx2Addr(1), codehash[:]))
	self.contracts[HashRegAddr[2:]][key] = hash.Hex()
}

func (self *testBackend) initUrlHint() {
	self.contracts[UrlHintAddr[2:]] = make(map[string]string)
	mapaddr := storageMapping(storageIdx2Addr(1), hash[:])

	key := storageAddress(storageFixedArray(mapaddr, storageIdx2Addr(0)))
	self.contracts[UrlHintAddr[2:]][key] = common.ToHex([]byte(url))
	key = storageAddress(storageFixedArray(mapaddr, storageIdx2Addr(1)))
	self.contracts[UrlHintAddr[2:]][key] = "0x0"
}

func (self *testBackend) StorageAt(ca, sa string) (res string) {
	c := self.contracts[ca]
	if c == nil {
		return "0x0"
	}
	res = c[sa]
	return
}

func (self *testBackend) Transact(fromStr, toStr, nonceStr, valueStr, gasStr, gasPriceStr, codeStr string) (string, error) {
	return "", nil
}

func (self *testBackend) Call(fromStr, toStr, valueStr, gasStr, gasPriceStr, codeStr string) (string, string, error) {
	return "", "", nil
}

func TestSetGlobalRegistrar(t *testing.T) {
	b := NewTestBackend()
	res := New(b)
	_, err := res.SetGlobalRegistrar("addresshex", common.BigToAddress(common.Big1))
	if err != nil {
		t.Errorf("unexpected error: %v'", err)
	}
}

func TestHashToHash(t *testing.T) {
	b := NewTestBackend()
	res := New(b)

	HashRegAddr = "0x0"
	got, err := res.HashToHash(codehash)
	if err == nil {
		t.Errorf("expected error")
	} else {
		exp := "HashReg address is not set"
		if err.Error() != exp {
			t.Errorf("incorrect error, expected '%v', got '%v'", exp, err.Error())
		}
	}

	HashRegAddr = common.BigToAddress(common.Big1).Hex() //[2:]
	got, err = res.HashToHash(codehash)
	if err == nil {
		t.Errorf("expected error")
	} else {
		exp := "HashToHash: content hash not found for '" + codehash.Hex() + "'"
		if err.Error() != exp {
			t.Errorf("incorrect error, expected '%v', got '%v'", exp, err.Error())
		}
	}

	b.initHashReg()
	got, err = res.HashToHash(codehash)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	} else {
		if got != hash {
			t.Errorf("incorrect result, expected '%v', got '%v'", hash.Hex(), got.Hex())
		}
	}
}

func storageFixedArray(addr, idx []byte) []byte {
	var carry byte
	for i := 31; i >= 0; i-- {
		var b byte = addr[i] + idx[i] + carry
		if b < addr[i] {
			carry = 1
		} else {
			carry = 0
		}
		addr[i] = b
	}
	return addr
}
