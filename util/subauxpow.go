package util

import (
	"bytes"
	"fmt"
	"io"

	"github.com/kar98kar/go-ulogos/common"
)

type SubAuxHead struct {
	SubAuxBranch [][]common.Hash
	SubAuxNonce  []uint32
}

func NewSubAuxHead() *SubAuxHead {
	return &SubAuxHead{}
}

func (a *SubAuxHead) Init(auxBytes []byte) error {
	r := bytes.NewReader(auxBytes)
	err := a.Deserialize(r)
	return err
}

func (a *SubAuxHead) Deserialize(r io.Reader) error {
	chainIDLayers, err := binarySerializer.Uint8(r)
	if err != nil {
		return err
	}

	for i := 0; i < int(chainIDLayers); i++ {
		branchLen, err := binarySerializer.Uint8(r)
		// BtcMerkleBranch
		var branch []common.Hash
		for j := 0; j < int(branchLen); j++ {
			hash := make([]byte, common.HashLength)
			_, err := io.ReadFull(r, hash)
			if err != nil {
				return err
			}
			branch = append(branch, common.BytesToHash(hash))
		}
		a.SubAuxBranch = append(a.SubAuxBranch, branch)

		nonce, err := binarySerializer.Uint32(r, littleEndian)
		if err != nil {
			return err
		}
		a.SubAuxNonce = append(a.SubAuxNonce, nonce)
	}

	return nil
}

func (a *SubAuxHead) GetAuxPowKey(key string, chainID []int) (auxpowKey string, err error) {
	var rootHash common.Hash

	for i := (len(chainID) - 1); i >= 0; i-- {
		rootHash = common.HexToHash(common.ReverseByByte(key))
		index := GetExpectedIndex(int(a.SubAuxNonce[i]), chainID[i], uint(len(a.SubAuxBranch[i])))
		rootHash = ComputeMerkleRootFromBranch(rootHash, a.SubAuxBranch[i], uint32(index))
		height := uint(len(a.SubAuxBranch[i]))
		var srcStr string
		srcStr = common.ReverseByByte(fmt.Sprintf("%x", rootHash))
		srcStr += common.ReverseByByte(fmt.Sprintf("%0.8x", 1<<height))
		srcStr += common.ReverseByByte(fmt.Sprintf("%0.8x", a.SubAuxNonce[i]))
		fmt.Printf("srcStr[%v]\n", srcStr)
		key = fmt.Sprintf("%x", DoubleHashH(common.Hex2Bytes(srcStr)))
		key = common.ReverseByByte(key)
		fmt.Printf("chainID[%v]key[%v]\n", chainID[i], key)
	}

	auxpowKey = key
	return auxpowKey, nil
}
