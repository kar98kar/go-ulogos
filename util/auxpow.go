package util

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ethereumproject/go-ethereum/common"
)

type AuxHead struct {
	Coinbase              MsgTx
	BtcBlkHeadHash        common.Hash
	BtcMerkleBranchLength uint8
	BtcMerkleBranch       []common.Hash
	BtcMerkleBranchIndex  uint32
	AuxMerkleBranchLength uint8
	AuxMerkleBranch       []common.Hash
	AuxMerkleBranchIndex  uint32
	BtcBlkHead            BitcoinBlockHeader
	SubAuxMerkleBranch    []common.Hash // version 2

	Version       int
	AuxMerkleRoot common.Hash
}

func NewAuxHead() *AuxHead {
	return &AuxHead{}
}

func (a *AuxHead) SetVersion(v int) {
	a.Version = v
}

func (a *AuxHead) GetVersion() int {
	return a.Version
}

func (a *AuxHead) Init(auxBytes []byte) error {
	r := bytes.NewReader(auxBytes)
	err := a.Deserialize(r)
	return err
}

func (a *AuxHead) Bytes() ([]byte, error) {
	w := bytes.NewBuffer(nil)
	err := a.Serialize(w)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func (a *AuxHead) Deserialize(r io.Reader) error {
	// Coinbase
	err := a.Coinbase.Deserialize(r)
	if err != nil {
		return err
	}

	// BtcBlkHeadHash
	BtcBlkHeadHash := make([]byte, common.HashLength)
	_, err = io.ReadFull(r, BtcBlkHeadHash)
	if err != nil {
		return err
	}
	a.BtcBlkHeadHash = common.BytesToHash(BtcBlkHeadHash)

	// BtcMerkleBranchLength
	a.BtcMerkleBranchLength, err = binarySerializer.Uint8(r)
	if err != nil {
		return err
	}

	// BtcMerkleBranch
	for i := 0; i < int(a.BtcMerkleBranchLength); i++ {
		hash := make([]byte, common.HashLength)
		_, err := io.ReadFull(r, hash)
		if err != nil {
			return err
		}
		a.BtcMerkleBranch = append(a.BtcMerkleBranch, common.BytesToHash(hash))
	}

	// BtcMerkleBranchIndex
	a.BtcMerkleBranchIndex, err = binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}

	// AuxMerkleBranchLength
	a.AuxMerkleBranchLength, err = binarySerializer.Uint8(r)
	if err != nil {
		return err
	}

	// AuxMerkleBranch
	for i := 0; i < int(a.AuxMerkleBranchLength); i++ {
		hash := make([]byte, common.HashLength)
		_, err = io.ReadFull(r, hash)
		if err != nil {
			return err
		}
		a.AuxMerkleBranch = append(a.AuxMerkleBranch, common.BytesToHash(hash))
	}

	// aux merkle root in coinbase
	bs := a.Coinbase.Bytes()
	magic := "fabe6d6d"
	coinbaseHex := fmt.Sprintf("%x", bs)
	idx := strings.Index(coinbaseHex, magic)
	if idx == -1 {
		return fmt.Errorf("magic number not exist")
	}
	idx += 8
	a.AuxMerkleRoot = common.HexToHash(common.ReverseByByte(coinbaseHex[idx : idx+64]))
	idx += 64

	// check merkle size and aux branch
	merkleSizeStr := coinbaseHex[idx : idx+8]
	idx += 8
	cbmerkleSize, err := strconv.ParseUint(common.ReverseByByte(merkleSizeStr), 16, 64)
	if err != nil {
		return err
	}
	subMerkleSizeBytes := a.BtcBlkHeadHash[20:28]
	rr := bytes.NewReader(subMerkleSizeBytes)
	subMerkleSize, err := binarySerializer.Uint32(rr, littleEndian)
	if err != nil {
		return err
	}
	auxBranchLength := uint(len(a.AuxMerkleBranch))
	cbBranchLength := GetLog2(uint(cbmerkleSize))
	subBranchLength := GetLog2(uint(subMerkleSize))

	if subBranchLength == 0 {
		a.SetVersion(1)
	} else if cbBranchLength == auxBranchLength {
		a.SetVersion(1)
	} else if (auxBranchLength - cbBranchLength) == subBranchLength {
		a.SetVersion(2)
	} else {
		return fmt.Errorf("len in coinbase:[%v], aux branch len[%v], sub branch len[%v]", cbBranchLength, auxBranchLength, subBranchLength)
	}

	// AuxMerkleBranchIndex
	a.AuxMerkleBranchIndex, err = binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}

	err = a.BtcBlkHead.Deserialize(r)
	if err != nil {
		return err
	}

	return nil
}

func (a *AuxHead) Serialize(w io.Writer) error {
	// Coinbase
	err := a.Coinbase.Serialize(w)
	if err != nil {
		return err
	}

	// BtcBlkHeadHash
	_, err = w.Write(a.BtcBlkHeadHash[:])
	if err != nil {
		return err
	}

	// BtcMerkleBranchLength
	err = binarySerializer.PutUint8(w, a.BtcMerkleBranchLength)
	if err != nil {
		return err
	}

	// BtcMerkleBranch
	for i := 0; i < int(a.BtcMerkleBranchLength); i++ {
		_, err = w.Write(a.BtcMerkleBranch[i][:])
		if err != nil {
			return err
		}
	}

	// BtcMerkleBranchIndex
	err = binarySerializer.PutUint32(w, littleEndian, a.BtcMerkleBranchIndex)
	if err != nil {
		return err
	}

	// AuxMerkleBranchLength
	err = binarySerializer.PutUint8(w, a.AuxMerkleBranchLength)
	if err != nil {
		return err
	}

	// AuxMerkleBranch
	for i := 0; i < int(a.AuxMerkleBranchLength); i++ {
		_, err = w.Write(a.AuxMerkleBranch[i][:])
		if err != nil {
			return err
		}
	}

	// sub merkle branch
	if a.GetVersion() == 2 {
		for _, v := range a.SubAuxMerkleBranch {
			_, err = w.Write(v[:])
			if err != nil {
				return err
			}
		}
	}

	// AuxMerkleBranchIndex
	err = binarySerializer.PutUint32(w, littleEndian, a.AuxMerkleBranchIndex)
	if err != nil {
		return err
	}

	err = a.BtcBlkHead.Serialize(w)
	if err != nil {
		return err
	}

	return nil
}
func (a *AuxHead) VerifySub(subKeyHash common.Hash, subChainID int) error {
	// 6.1 sub tree id
	if a.GetVersion() == 2 {
		subMerkleSizeBytes := a.BtcBlkHeadHash[20:28]
		rr := bytes.NewReader(subMerkleSizeBytes)
		subMerkleSize, err := binarySerializer.Uint32(rr, littleEndian)
		if err != nil {
			return err
		}
		subMerkleNonce, err := binarySerializer.Uint32(rr, littleEndian)
		if err != nil {
			return err
		}

		subIndex := GetExpectedIndex(int(subMerkleNonce), subChainID, GetLog2(uint(subMerkleSize)))
		subauxMerkleRootActual := common.ComputeMerkleRootFromBranch(subKeyHash, a.SubAuxMerkleBranch, uint32(subIndex))
		if subauxMerkleRootActual != a.BtcBlkHeadHash {
			return fmt.Errorf("check sub merkle branch failed")
		}
	}
	return nil
}

func (a *AuxHead) Verify(key string, target uint32, chainID int) error {
	keyHash := common.HexToHash(common.ReverseByByte(key))
	// 0. init coinbase
	bs := a.Coinbase.Bytes()

	// 1. check magic number
	magic := "fabe6d6d"
	coinbaseHex := fmt.Sprintf("%x", bs)
	idx := strings.Index(coinbaseHex, magic)
	if idx == -1 {
		return fmt.Errorf("magic number not exist")
	}
	idx += 8  // skip magic number
	idx += 64 // skip hash
	idx += 8  // skip merkle size

	// 3. check merkle nonce
	merkleNonceStr := coinbaseHex[idx : idx+8]
	merkleNonce, err := strconv.ParseUint(common.ReverseByByte(merkleNonceStr), 16, 64)
	if err != nil {
		return err
	}
	calcAuxMMIndex := GetExpectedIndex(int(merkleNonce), chainID, uint(len(a.AuxMerkleBranch)))
	if calcAuxMMIndex != int(a.AuxMerkleBranchIndex) {
		return fmt.Errorf("index not same, calc from chainid:[%v], actual:[%v], merkleNonce:[%v], chainID:[%v], height[%v]", calcAuxMMIndex, a.AuxMerkleBranchIndex, int(merkleNonce), chainID, uint(len(a.AuxMerkleBranch)))
	}

	// 4. check aux merkle root in coinbase
	auxMerkleRootActual := common.ComputeMerkleRootFromBranch(keyHash, a.AuxMerkleBranch, uint32(a.AuxMerkleBranchIndex))
	if auxMerkleRootActual != a.AuxMerkleRoot {
		return fmt.Errorf("aux merkle root from branch[%x] diff with from coinbase[%x]", auxMerkleRootActual, a.AuxMerkleRoot)
	}

	// 5. calc coinbase hash and merkle root
	bitcoinMerkleRootActual := common.ComputeMerkleRootFromBranch(common.Hash(a.Coinbase.TxHash()), a.BtcMerkleBranch, uint32(a.BtcMerkleBranchIndex))
	if a.BtcBlkHead.MerkleRoot != bitcoinMerkleRootActual {
		return fmt.Errorf("btc merkle root error, expect[%x], actual[%x]", a.BtcBlkHead.PrevBlock, bitcoinMerkleRootActual)
	}

	// 6. calc blk header hash
	// if a.BtcBlkHead.BlockHash() != a.BtcBlkHeadHash {
	// 	return fmt.Errorf("blk header hash not equal, expect:[%x], actual[%x]", a.BtcBlkHead.BlockHash(), a.BtcBlkHeadHash)
	// }

	// 7. calc parent blk header hash (pow)
	if !a.BtcBlkHead.CheckProofOfWorkCY(target) {
		return fmt.Errorf("pow failed")
	}

	return nil
}

func GetExpectedIndex(nNonce int, nChainID int, h uint) int {

	rand := nNonce
	rand = rand*1103515245 + 12345
	rand += nChainID
	rand = rand*1103515245 + 12345

	return rand % (1 << uint(h))
}

func GetLog2(x uint) uint {
	for i := uint(1); i < 32; i++ {
		if (1 << i) != x {
			continue
		}
		return i
	}
	return 0
}

func ReverseByByte(s string) string {
	var str string
	length := len(s)
	for i := 0; (i * 2) < length; i++ {
		str += string(s[length-i*2-2])
		str += string(s[length-i*2-1])
	}
	return str
}