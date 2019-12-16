package util

import (
	"crypto/sha256"

	"github.com/kar98kar/go-ulogos/common"
)

func DoubleHashH(b []byte) common.Hash {
	first := sha256.Sum256(b)
	return common.Hash(sha256.Sum256(first[:]))
}

func HashMerkleBranches(left *common.Hash, right *common.Hash) *common.Hash {
	var hash [common.HashLength * 2]byte
	copy(hash[:common.HashLength], left[:])
	copy(hash[common.HashLength:], right[:])

	newHash := DoubleHashH(hash[:])
	return &newHash
}

func ComputeMerkleRootFromBranch(leaf common.Hash, vMerkleBranch []common.Hash, nIndex uint32) common.Hash {
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
