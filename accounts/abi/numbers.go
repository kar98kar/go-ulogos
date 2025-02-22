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

package abi

import (
	"math/big"
	"reflect"

	"github.com/kar98kar/go-ulogos/common"
)

var (
	big_t     = reflect.TypeOf(big.Int{})
	ubig_t    = reflect.TypeOf(big.Int{})
	int_t     = reflect.TypeOf(int(0))
	int8_t    = reflect.TypeOf(int8(0))
	int16_t   = reflect.TypeOf(int16(0))
	int32_t   = reflect.TypeOf(int32(0))
	int64_t   = reflect.TypeOf(int64(0))
	address_t = reflect.TypeOf(common.Address{})

	int_ts   = reflect.TypeOf([]int(nil))
	int8_ts  = reflect.TypeOf([]int8(nil))
	int16_ts = reflect.TypeOf([]int16(nil))
	int32_ts = reflect.TypeOf([]int32(nil))
	int64_ts = reflect.TypeOf([]int64(nil))
)

// U256 converts a big Int into a 256bit EVM number.
func U256(n *big.Int) []byte {
	return common.LeftPadBytes(common.U256(n).Bytes(), 32)
}

// packNum packs the given number (using the reflect value) and will cast it to appropriate number representation
func packNum(value reflect.Value) []byte {
	switch kind := value.Kind(); kind {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return U256(new(big.Int).SetUint64(value.Uint()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return U256(big.NewInt(value.Int()))
	case reflect.Ptr:
		return U256(value.Interface().(*big.Int))
	}
	return nil
}

// checks whether the given reflect value is signed. This also works for slices with a number type
func isSigned(v reflect.Value) bool {
	switch v.Type() {
	case int_ts, int8_ts, int16_ts, int32_ts, int64_ts, int_t, int8_t, int16_t, int32_t, int64_t:
		return true
	}
	return false
}
