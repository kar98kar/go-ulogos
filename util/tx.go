// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"bytes"
	"fmt"
	"io"

	"crypto/sha256"
	"encoding/hex"
	"github.com/kar98kar/go-ulogos/common"
)

const MaxMessagePayload = (1024 * 1024 * 32) // 32MB
const MaxBlockPayload = 1000000              // Not actually 1MB which would be 1024 * 1024
const HashSize = 32

func DoubleHashHH(b []byte) chainHash {
	first := sha256.Sum256(b)
	return chainHash(sha256.Sum256(first[:]))
}

const (
	minTxInPayload        = 9 + common.HashLength
	maxTxInPerMessage     = (MaxMessagePayload / minTxInPayload) + 1
	minTxOutPayload       = 9
	maxTxOutPerMessage    = (MaxMessagePayload / minTxOutPayload) + 1
	freeListMaxScriptSize = 512
	freeListMaxItems      = 12500
)

type chainHash [HashSize]byte

type scriptFreeList chan []byte

func (c scriptFreeList) Borrow(size uint64) []byte {
	if size > freeListMaxScriptSize {
		return make([]byte, size)
	}

	var buf []byte
	select {
	case buf = <-c:
	default:
		buf = make([]byte, freeListMaxScriptSize)
	}
	return buf[:size]
}

func (c scriptFreeList) Return(buf []byte) {
	if cap(buf) != freeListMaxScriptSize {
		return
	}

	select {
	case c <- buf:
	default:
	}
}

var scriptPool scriptFreeList = make(chan []byte, freeListMaxItems)

type OutPoint struct {
	Hash  chainHash
	Index uint32
}

func (hash chainHash) String() string {
	for i := 0; i < HashSize/2; i++ {
		hash[i], hash[HashSize-1-i] = hash[HashSize-1-i], hash[i]
	}
	return hex.EncodeToString(hash[:])
}

type TxIn struct {
	PreviousOutPoint OutPoint
	SignatureScript  []byte
	Sequence         uint32
}

func (t *TxIn) SerializeSize() int {
	return 40 + VarIntSerializeSize(uint64(len(t.SignatureScript))) +
		len(t.SignatureScript)
}

type TxOut struct {
	Value    int64
	PkScript []byte
}

func (t *TxOut) SerializeSize() int {
	return 8 + VarIntSerializeSize(uint64(len(t.PkScript))) + len(t.PkScript)
}

type MsgTx struct {
	Version  int32
	TxIn     []*TxIn
	TxOut    []*TxOut
	LockTime uint32
}

// TxHash generates the Hash for the transaction.
func (msg *MsgTx) TxHash() chainHash {
	buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSize()))
	_ = msg.Serialize(buf)
	return DoubleHashHH(buf.Bytes())
}

func (msg *MsgTx) BtcDecode(r io.Reader, pver uint32) error {
	version, err := binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}
	msg.Version = int32(version)
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if count > uint64(maxTxInPerMessage) {
		str := fmt.Sprintf("too many input transactions to fit into "+
			"max message size [count %d, max %d]", count,
			maxTxInPerMessage)
		return fmt.Errorf("MsgTx.BtcDecode" + str)
	}

	returnScriptBuffers := func() {
		for _, txIn := range msg.TxIn {
			if txIn == nil || txIn.SignatureScript == nil {
				continue
			}
			scriptPool.Return(txIn.SignatureScript)
		}
		for _, txOut := range msg.TxOut {
			if txOut == nil || txOut.PkScript == nil {
				continue
			}
			scriptPool.Return(txOut.PkScript)
		}
	}

	// Deserialize the inputs.
	var totalScriptSize uint64
	txIns := make([]TxIn, count)
	msg.TxIn = make([]*TxIn, count)
	for i := uint64(0); i < count; i++ {
		ti := &txIns[i]
		msg.TxIn[i] = ti
		err = readTxIn(r, pver, msg.Version, ti)
		if err != nil {
			returnScriptBuffers()
			return err
		}
		totalScriptSize += uint64(len(ti.SignatureScript))
	}

	count, err = ReadVarInt(r, pver)
	if err != nil {
		returnScriptBuffers()
		return err
	}

	if count > uint64(maxTxOutPerMessage) {
		returnScriptBuffers()
		str := fmt.Sprintf("too many output transactions to fit into "+
			"max message size [count %d, max %d]", count,
			maxTxOutPerMessage)
		return fmt.Errorf("MsgTx.BtcDecode" + str)
	}

	txOuts := make([]TxOut, count)
	msg.TxOut = make([]*TxOut, count)
	for i := uint64(0); i < count; i++ {
		to := &txOuts[i]
		msg.TxOut[i] = to
		err = readTxOut(r, pver, msg.Version, to)
		if err != nil {
			returnScriptBuffers()
			return err
		}
		totalScriptSize += uint64(len(to.PkScript))
	}

	msg.LockTime, err = binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		returnScriptBuffers()
		return err
	}

	var offset uint64
	scripts := make([]byte, totalScriptSize)
	for i := 0; i < len(msg.TxIn); i++ {
		signatureScript := msg.TxIn[i].SignatureScript
		copy(scripts[offset:], signatureScript)

		scriptSize := uint64(len(signatureScript))
		end := offset + scriptSize
		msg.TxIn[i].SignatureScript = scripts[offset:end:end]
		offset += scriptSize

		scriptPool.Return(signatureScript)
	}
	for i := 0; i < len(msg.TxOut); i++ {
		pkScript := msg.TxOut[i].PkScript
		copy(scripts[offset:], pkScript)

		scriptSize := uint64(len(pkScript))
		end := offset + scriptSize
		msg.TxOut[i].PkScript = scripts[offset:end:end]
		offset += scriptSize

		scriptPool.Return(pkScript)
	}

	return nil
}

func (msg *MsgTx) Deserialize(r io.Reader) error {
	return msg.BtcDecode(r, 0)
}

func (msg *MsgTx) BtcEncode(w io.Writer, pver uint32) error {
	err := binarySerializer.PutUint32(w, littleEndian, uint32(msg.Version))
	if err != nil {
		return err
	}

	count := uint64(len(msg.TxIn))
	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, ti := range msg.TxIn {
		err = writeTxIn(w, pver, msg.Version, ti)
		if err != nil {
			return err
		}
	}

	count = uint64(len(msg.TxOut))
	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, to := range msg.TxOut {
		err = writeTxOut(w, pver, msg.Version, to)
		if err != nil {
			return err
		}
	}

	return binarySerializer.PutUint32(w, littleEndian, msg.LockTime)
}

func (msg *MsgTx) Serialize(w io.Writer) error {
	return msg.BtcEncode(w, 0)
}

func (msg *MsgTx) Bytes() []byte {
	w := bytes.NewBuffer(nil)
	msg.Serialize(w)
	return w.Bytes()
}

func (msg *MsgTx) SerializeSize() int {
	n := 8 + VarIntSerializeSize(uint64(len(msg.TxIn))) +
		VarIntSerializeSize(uint64(len(msg.TxOut)))

	for _, txIn := range msg.TxIn {
		n += txIn.SerializeSize()
	}

	for _, txOut := range msg.TxOut {
		n += txOut.SerializeSize()
	}

	return n
}

func readOutPoint(r io.Reader, pver uint32, version int32, op *OutPoint) error {
	_, err := io.ReadFull(r, op.Hash[:])
	if err != nil {
		return err
	}

	op.Index, err = binarySerializer.Uint32(r, littleEndian)
	return err
}

func writeOutPoint(w io.Writer, pver uint32, version int32, op *OutPoint) error {
	_, err := w.Write(op.Hash[:])
	if err != nil {
		return err
	}

	return binarySerializer.PutUint32(w, littleEndian, op.Index)
}

func readScript(r io.Reader, pver uint32, maxAllowed uint32, fieldName string) ([]byte, error) {
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return nil, err
	}

	if count > uint64(maxAllowed) {
		str := fmt.Sprintf("%s is larger than the max allowed size "+
			"[count %d, max %d]", fieldName, count, maxAllowed)
		return nil, fmt.Errorf("readScript" + str)
	}

	b := scriptPool.Borrow(count)
	_, err = io.ReadFull(r, b)
	if err != nil {
		scriptPool.Return(b)
		return nil, err
	}
	return b, nil
}

func readTxIn(r io.Reader, pver uint32, version int32, ti *TxIn) error {
	err := readOutPoint(r, pver, version, &ti.PreviousOutPoint)
	if err != nil {
		return err
	}

	ti.SignatureScript, err = readScript(r, pver, MaxMessagePayload,
		"transaction input signature script")
	if err != nil {
		return err
	}

	return readElement(r, &ti.Sequence)
}

func writeTxIn(w io.Writer, pver uint32, version int32, ti *TxIn) error {
	err := writeOutPoint(w, pver, version, &ti.PreviousOutPoint)
	if err != nil {
		return err
	}

	err = WriteVarBytes(w, pver, ti.SignatureScript)
	if err != nil {
		return err
	}

	return binarySerializer.PutUint32(w, littleEndian, ti.Sequence)
}

func readTxOut(r io.Reader, pver uint32, version int32, to *TxOut) error {
	err := readElement(r, &to.Value)
	if err != nil {
		return err
	}

	to.PkScript, err = readScript(r, pver, MaxMessagePayload,
		"transaction output public key script")
	return err
}

func writeTxOut(w io.Writer, pver uint32, version int32, to *TxOut) error {
	err := binarySerializer.PutUint64(w, littleEndian, uint64(to.Value))
	if err != nil {
		return err
	}

	return WriteVarBytes(w, pver, to.PkScript)
}
