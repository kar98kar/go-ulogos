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

package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
)

const (
	HashLength    = 32
	AddressLength = 21
)

var hashJsonLengthErr = errors.New("common: unmarshalJSON failed: hash must be exactly 32 bytes")

type (
	Hash    [HashLength]byte
	Address [AddressLength]byte
)

func BytesToHash(b []byte) Hash {
	var h Hash
	h.SetBytes(b)
	return h
}
func BigToHash(b *big.Int) Hash { return BytesToHash(b.Bytes()) }
func HexToHash(s string) Hash   { return BytesToHash(FromHex(s)) }

// Don't use the default 'String' method in case we want to overwrite

// Get the string representation of the underlying hash
func (h Hash) Str() string   { return string(h[:]) }
func (h Hash) Bytes() []byte { return h[:] }
func (h Hash) Big() *big.Int { return new(big.Int).SetBytes(h[:]) }
func (h Hash) Hex() string   { return "0x" + Bytes2Hex(h[:]) }

// UnmarshalJSON parses a hash in its hex from to a hash.
func (h *Hash) UnmarshalJSON(input []byte) error {
	length := len(input)
	if length >= 2 && input[0] == '"' && input[length-1] == '"' {
		input = input[1 : length-1]
	}
	// strip "0x" for length check
	if len(input) > 1 && strings.ToLower(string(input[:2])) == "0x" {
		input = input[2:]
	}

	// validate the length of the input hash
	if len(input) != HashLength*2 {
		return hashJsonLengthErr
	}
	h.SetBytes(FromHex(string(input)))
	return nil
}

// Serialize given hash to JSON
func (h Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.Hex())
}

// Sets the hash to the value of b. If b is larger than len(h) it will panic
func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h.Bytes()) {
		b = b[len(b)-HashLength:]
	}

	copy(h[HashLength-len(b):], b)
}

// Set string `s` to h. If s is larger than len(h) it will panic
func (h *Hash) SetString(s string) { h.SetBytes([]byte(s)) }

// Sets h to other
func (h *Hash) Set(other Hash) {
	for i, v := range other {
		h[i] = v
	}
}

// Generate implements testing/quick.Generator.
func (h Hash) Generate(rand *rand.Rand, size int) reflect.Value {
	m := rand.Intn(len(h))
	for i := len(h) - 1; i > m; i-- {
		h[i] = byte(rand.Uint32())
	}
	return reflect.ValueOf(h)
}

func EmptyHash(h Hash) bool {
	return h == Hash{}
}

func (h Hash) IsEmpty() bool {
	return EmptyHash(h)
}

/////////// Address
func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}
func StringToAddress(s string) Address { return BytesToAddress([]byte(s)) }
func BigToAddress(b *big.Int) Address  { return BytesToAddress(b.Bytes()) }
func HexToAddress(s string) Address    { return BytesToAddress(FromHex(s)) }

func EmptyAddress(a Address) bool {
	return a == Address{}
}

func (a Address) IsEmpty() bool {
	return EmptyAddress(a)
}

// IsHexAddress verifies whether a string can represent a valid hex-encoded
// Ethereum address or not.
func IsHexAddress(s string) bool {
	if len(s) == 2+2*AddressLength && IsHex(s) {
		return true
	}
	if len(s) == 2*AddressLength && IsHex("0x"+s) {
		return true
	}
	return false
}

// Get the string representation of the underlying address
func (a Address) Str() string   { return string(a[:]) }
func (a Address) Bytes() []byte { return a[:] }
func (a Address) Big() *big.Int { return new(big.Int).SetBytes(a[:]) }
func (a Address) Hash() Hash    { return BytesToHash(a[:]) }
func (a Address) Hex() string   { return "0x" + Bytes2Hex(a[:]) }

// Sets the address to the value of b. If b is larger than len(a) it will panic
func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a.Bytes()) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

// Set string `s` to a. If s is larger than len(a) it will panic
func (a *Address) SetString(s string) { a.SetBytes([]byte(s)) }

// Sets a to other
func (a *Address) Set(other Address) {
	for i, v := range other {
		a[i] = v
	}
}

// Serialize given address to JSON
func (a Address) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.Hex())
}

// Parse address from raw json data
func (a *Address) UnmarshalJSON(data []byte) error {
	if len(data) > 2 && data[0] == '"' && data[len(data)-1] == '"' {
		data = data[1 : len(data)-1]
	}

	if len(data) > 2 && data[0] == '0' && data[1] == 'x' {
		data = data[2:]
	}

	if len(data) != 2*AddressLength {
		return fmt.Errorf("Invalid address length, expected %d got %d bytes", 2*AddressLength, len(data))
	}

	n, err := hex.Decode(a[:], data)
	if err != nil {
		return err
	}

	if n != AddressLength {
		return fmt.Errorf("Invalid address")
	}

	a.Set(HexToAddress(string(data)))
	return nil
}

// PP Pretty Prints a byte slice in the following format:
// 	hex(value[:4])...(hex[len(value)-4:])
func PP(value []byte) string {
	if len(value) <= 8 {
		return Bytes2Hex(value)
	}

	return fmt.Sprintf("%x...%x", value[:4], value[len(value)-4])
}

// CY
func ReverseByByte(s string) string {
	var str string
	length := len(s)
	for i := 0; (i * 2) < length; i++ {
		str += string(s[length-i*2-2])
		str += string(s[length-i*2-1])
	}
	return str
}

// CY
func ConvertHexToByte(str string) Hash {
	if (len(str)%2 != 0) || (len(str) > (2 * HashLength)) {
		fmt.Println("Wrong format!")
		return Hash{}
	}
	var result Hash
	for i := 0; (i * 2) < len(str); i++ {
		b, _ := strconv.ParseInt(str[2*i:2*i+2], 16, 9)
		result[i] = byte(b)
	}
	return result
}

// DoubleHashH calculates hash(hash(b)) and returns the resulting bytes as a
// Hash.
func DoubleHashH(b []byte) Hash {
	first := sha256.Sum256(b)
	return Hash(sha256.Sum256(first[:]))
}

// HashMerkleBranches takes two hashes, treated as the left and right tree
// nodes, and returns the hash of their concatenation.  This is a helper
// function used to aid in the generation of a merkle tree.
func HashMerkleBranches(left *Hash, right *Hash) *Hash {
	// Concatenate the left and right nodes.
	var hash [HashLength * 2]byte
	copy(hash[:HashLength], left[:])
	copy(hash[HashLength:], right[:])

	newHash := DoubleHashH(hash[:])
	return &newHash
}

/* This implements a constant-space merkle root/path calculator, limited to 2^32 leaves. */
func MerkleComputation(leaves []Hash, proot *Hash, pmutated *bool, branchpos uint32, pbranch *[]Hash) error {
	if pbranch != nil {
		*pbranch = []Hash{}
	}
	ll := len(leaves)
	lenleaves := uint32(ll)
	if lenleaves == 0 {
		if pmutated != nil {
			*pmutated = false
		}
		if proot != nil {
			*proot = Hash{}
		}
		return fmt.Errorf("%s", "Length of leaves if 0")
	}
	mutated := false
	// count is the number of leaves processed so far.
	var count uint32
	// inner is an array of eagerly computed subtree hashes, indexed by tree
	// level (0 being the leaves).
	// For example, when count is 25 (11001 in binary), inner[4] is the hash of
	// the first 16 leaves, inner[3] of the next 8 leaves, and inner[0] equal to
	// the last leaf. The other inner entries are undefined.
	var inner [32]Hash
	// Which position in inner is a hash that depends on the matching leaf.
	matchlevel := -1
	// First process all leaves into 'inner' values.
	for count < lenleaves {
		h := leaves[count]
		matchh := count == branchpos
		count++
		var level uint32
		// For each of the lower bits in count that are 0, do 1 step. Each
		// corresponds to an inner value that existed before processing the
		// current leaf, and each needs a hash to combine it.
		for level = 0; (count & (1 << level)) == 0; level++ {
			if pbranch != nil {
				if matchh {
					*pbranch = append(*pbranch, inner[level])
				} else if matchlevel == int(level) {
					*pbranch = append(*pbranch, h)
					matchh = true
				}
			}
			if inner[level] == h {
				mutated = true
			}
			h = *HashMerkleBranches(&inner[level], &h)
		}
		// Store the resulting hash at inner position level.
		inner[level] = h
		if matchh {
			matchlevel = int(level)
		}
	}
	// Do a final 'sweep' over the rightmost branch of the tree to process
	// odd levels, and reduce everything to a single top value.
	// Level is the level (counted from the bottom) up to which we've sweeped.
	var level uint32
	// As long as bit number level in count is zero, skip it. It means there
	// is nothing left at this level.
	for (count & (1 << level)) == 0 {
		level++
	}
	h := inner[level]
	matchh := matchlevel == int(level)
	for count != (1 << level) {
		// If we reach this point, h is an inner value that is not the top.
		// We combine it with itself (Bitcoin's special rule for odd levels in
		// the tree) to produce a higher level one.
		if (pbranch != nil) && matchh {
			*pbranch = append(*pbranch, h)
		}
		h = *HashMerkleBranches(&h, &h)
		// forRootHash = h
		// Increment count to the value it would have if two entries at this
		// level had existed.
		count += (1 << level)
		level++
		// And propagate the result upwards accordingly.
		for (count & (1 << level)) == 0 {
			if pbranch != nil {
				if matchh {
					*pbranch = append(*pbranch, inner[level])
				} else if matchlevel == int(level) {
					*pbranch = append(*pbranch, h)
					matchh = true
				}
			}
			h = *HashMerkleBranches(&inner[level], &h)
			level++
		}
	}
	// Return result.
	if pmutated != nil {
		*pmutated = mutated
	}
	if proot != nil {
		*proot = h
	}

	return nil
}

func nextPowerOfTwo(n int) int {
	// Return the number if it's already a power of 2.
	if n&(n-1) == 0 {
		return n
	}

	// Figure out and return the next power of two.
	exponent := uint(math.Log2(float64(n))) + 1
	return 1 << exponent // 2^exponent
}

func BuildMerkleTreeStore(transactions [][]byte) []*Hash {
	// Calculate how many entries are required to hold the binary merkle
	// tree as a linear array and create an array of that size.
	nextPoT := nextPowerOfTwo(len(transactions))
	arraySize := nextPoT*2 - 1
	merkles := make([]*Hash, arraySize)

	// Create the base transaction hashes and populate the array with them.
	for i, tx := range transactions {
		h := DoubleHashH(tx)
		merkles[i] = &h
	}

	// Start the array offset after the last transaction and adjusted to the
	// next power of two.
	offset := nextPoT
	for i := 0; i < arraySize-1; i += 2 {
		switch {
		// When there is no left child node, the parent is nil too.
		case merkles[i] == nil:
			merkles[offset] = nil

		// When there is no right child, the parent is generated by
		// hashing the concatenation of the left child with itself.
		case merkles[i+1] == nil:
			newHash := HashMerkleBranches(merkles[i], merkles[i])
			merkles[offset] = newHash

		// The normal case sets the parent node to the double sha256
		// of the concatentation of the left and right children.
		default:
			newHash := HashMerkleBranches(merkles[i], merkles[i+1])
			merkles[offset] = newHash
		}
		offset++
	}

	return merkles
}

func computeMerkleRoot(leaves []Hash, mutated *bool) Hash {
	hash := Hash{}
	MerkleComputation(leaves, &hash, mutated, 0xffffffff, nil)
	return hash
}

func computeMerkleBranch(leaves []Hash, position uint32) []Hash {
	var ret []Hash
	MerkleComputation(leaves, nil, nil, position, &ret)
	return ret
}

func ComputeMerkleRootFromBranch(leaf Hash, vMerkleBranch []Hash, nIndex uint32) Hash {
	hash := leaf
	for _, ele := range vMerkleBranch {
		if (nIndex & 1) != 0 {
			hash = *HashMerkleBranches(&ele, &hash)
		} else {
			hash = *HashMerkleBranches(&hash, &ele)
		}
		nIndex >>= 1
	}
	return hash
}

func Hash4mmMerkleRoot(txs [][]byte, mutated *bool) Hash {
	var leaves []Hash
	for _, ele := range txs {
		leaves = append(leaves, DoubleHashH(ele))
	}

	return computeMerkleRoot(leaves, mutated)
}

func hash4mmWitnessMerkleRoot(txs [][]byte, mutated *bool) Hash {
	var leaves []Hash
	first := true
	for _, ele := range txs {
		if first {
			leaves = append(leaves, Hash{})
			first = false
		} else {
			leaves = append(leaves, DoubleHashH(ele))
		}
	}

	return computeMerkleRoot(leaves, mutated)
}

func Hash4mmMerkleBranch(txs [][]byte, position uint32) []Hash {
	var leaves []Hash
	for _, ele := range txs {
		leaves = append(leaves, DoubleHashH(ele))
	}
	return computeMerkleBranch(leaves, position)
}

type BitCoinHead struct {
	Version      int32
	PreviousHash string
	MerkleRoot   string
	CurTime      int64
	Bits         string
	Nonce        uint32
	Coinbase     string
	MerkleBranch []string
	TxIndex      int32
}
