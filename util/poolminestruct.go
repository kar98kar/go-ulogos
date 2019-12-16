package util

import (
	"bytes"
	"io"
	"math/big"
	"time"

	"github.com/kar98kar/go-ulogos/common"
)

const MaxBlockHeaderPayload = 16 + (common.HashLength * 2)

type BitcoinBlockHeader struct {
	Version    int32
	PrevBlock  common.Hash
	MerkleRoot common.Hash
	Timestamp  time.Time
	Bits       uint32
	Nonce      uint32
}

func (h *BitcoinBlockHeader) Serialize(w io.Writer) error {
	return writeBlockHeader(w, 0, h)
}

func (h *BitcoinBlockHeader) Deserialize(r io.Reader) error {
	return readBlockHeader(r, 0, h)
}
func (h *BitcoinBlockHeader) BlockHash() common.Hash {
	buf := bytes.NewBuffer(make([]byte, 0, MaxBlockHeaderPayload))
	_ = writeBlockHeader(buf, 0, h)

	return DoubleHashH(buf.Bytes())
}

func (h *BitcoinBlockHeader) Bytes() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, MaxBlockHeaderPayload))
	_ = writeBlockHeader(buf, 0, h)
	return buf.Bytes()
}

func (h *BitcoinBlockHeader) CheckProofOfWorkCY(target uint32) bool {
	targetDifficulty := CompactToBig(target)

	hash := h.BlockHash()
	hashNum := HashToBig(&hash)
	if hashNum.Cmp(targetDifficulty) <= 0 {
		return true
	}
	return false
}

func CompactToBig(compact uint32) *big.Int {
	mantissa := compact & 0x007fffff
	isNegative := compact&0x00800000 != 0
	exponent := uint(compact >> 24)

	var bn *big.Int
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		bn = big.NewInt(int64(mantissa))
	} else {
		bn = big.NewInt(int64(mantissa))
		bn.Lsh(bn, 8*(exponent-3))
	}

	if isNegative {
		bn = bn.Neg(bn)
	}

	return bn
}

func BigToCompact(n *big.Int) uint32 {
	// No need to do any work if it's zero.
	if n.Sign() == 0 {
		return 0
	}

	// Since the base for the exponent is 256, the exponent can be treated
	// as the number of bytes.  So, shift the number right or left
	// accordingly.  This is equivalent to:
	// mantissa = mantissa / 256^(exponent-3)
	var mantissa uint32
	exponent := uint(len(n.Bytes()))
	if exponent <= 3 {
		mantissa = uint32(n.Bits()[0])
		mantissa <<= 8 * (3 - exponent)
	} else {
		// Use a copy to avoid modifying the caller's original number.
		tn := new(big.Int).Set(n)
		mantissa = uint32(tn.Rsh(tn, 8*(exponent-3)).Bits()[0])
	}

	// When the mantissa already has the sign bit set, the number is too
	// large to fit into the available 23-bits, so divide the number by 256
	// and increment the exponent accordingly.
	if mantissa&0x00800000 != 0 {
		mantissa >>= 8
		exponent++
	}

	// Pack the exponent, sign bit, and mantissa into an unsigned 32-bit
	// int and return it.
	compact := uint32(exponent<<24) | mantissa
	if n.Sign() < 0 {
		compact |= 0x00800000
	}
	return compact
}

func HashToBig(hash *common.Hash) *big.Int {
	buf := *hash
	blen := len(buf)
	for i := 0; i < blen/2; i++ {
		buf[i], buf[blen-1-i] = buf[blen-1-i], buf[i]
	}
	return new(big.Int).SetBytes(buf[:])
}

type BBlockHeader struct {
	// Version of the block.  This is not the same as the protocol version.
	Version int32

	// Hash of the previous block in the block chain.
	PrevBlock chainHash

	// Merkle tree reference to hash of all transactions for the block.
	MerkleRoot chainHash

	// Time the block was created.  This is, unfortunately, encoded as a
	// uint32 on the wire and therefore is limited to 2106.
	Timestamp time.Time

	// Difficulty target for the block.
	Bits uint32

	// Nonce used to generate the block.
	Nonce uint32
}
