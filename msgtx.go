package zecutil

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// MsgTx zec fork
type MsgTx struct {
	*wire.MsgTx
	ExpiryHeight uint32
}

// witnessMarkerBytes are a pair of bytes specific to the witness encoding. If
// this sequence is encoutered, then it indicates a transaction has iwtness
// data. The first byte is an always 0x00 marker byte, which allows decoders to
// distinguish a serialized transaction with witnesses from a regular (legacy)
// one. The second byte is the Flag field, which at the moment is always 0x01,
// but may be extended in the future to accommodate auxiliary non-committed
// fields.
var witessMarkerBytes = []byte{0x00, 0x01}

// TxHash generates the Hash for the transaction.
func (msg *MsgTx) TxHash() chainhash.Hash {
	var buf bytes.Buffer
	_ = msg.ZecEncode(&buf, 0, wire.BaseEncoding)
	return chainhash.DoubleHashH(buf.Bytes())
}

// ZecEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding transactions to be stored to disk, such as in a
// database, as opposed to encoding transactions for the wire.
// msg.Version must be 3 or 4 and may or may not include the overwintered flag
func (msg *MsgTx) ZecEncode(w io.Writer, pver uint32, enc wire.MessageEncoding) error {
	err := binarySerializer.PutUint32(w, littleEndian, uint32(msg.Version)|(1<<31))
	if err != nil {
		return err
	}

	var versionGroupID = versionOverwinterGroupID
	if msg.Version == versionSapling {
		versionGroupID = versionSaplingGroupID
	}

	err = binarySerializer.PutUint32(w, littleEndian, versionGroupID)
	if err != nil {
		return err
	}

	// If the encoding nVersion is set to WitnessEncoding, and the Flags
	// field for the MsgTx aren't 0x00, then this indicates the transaction
	// is to be encoded using the new witness inclusionary structure
	// defined in BIP0144.
	doWitness := enc == wire.WitnessEncoding && msg.HasWitness()
	if doWitness {
		// After the txn's Version field, we include two additional
		// bytes specific to the witness encoding. The first byte is an
		// always 0x00 marker byte, which allows decoders to
		// distinguish a serialized transaction with witnesses from a
		// regular (legacy) one. The second byte is the Flag field,
		// which at the moment is always 0x01, but may be extended in
		// the future to accommodate auxiliary non-committed fields.
		if _, err := w.Write(witessMarkerBytes); err != nil {
			return err
		}
	}

	count := uint64(len(msg.MsgTx.TxIn))
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
		err = WriteTxOut(w, pver, msg.Version, to)
		if err != nil {
			return err
		}
	}

	// If this transaction is a witness transaction, and the witness
	// encoded is desired, then encode the witness for each of the inputs
	// within the transaction.
	if doWitness {
		for _, ti := range msg.TxIn {
			err = writeTxWitness(w, pver, msg.Version, ti.Witness)
			if err != nil {
				return err
			}
		}
	}

	if err = binarySerializer.PutUint32(w, littleEndian, msg.LockTime); err != nil {
		return err
	}

	if err = binarySerializer.PutUint32(w, littleEndian, msg.ExpiryHeight); err != nil {
		return err
	}

	if msg.Version == versionSapling {
		// valueBalance
		if err = binarySerializer.PutUint64(w, littleEndian, 0); err != nil {
			return err
		}
		// nShieldedSpend
		err = WriteVarInt(w, pver, 0)
		if err != nil {
			return err
		}

		// nShieldedOutput
		err = WriteVarInt(w, pver, 0)
		if err != nil {
			return err
		}
	}

	return WriteVarInt(w, pver, 0)
}

// WriteTxOut encodes to into the bitcoin protocol encoding for a transaction
// output (TxOut) to w.
//
// NOTE: This function is exported in order to allow txscript to compute the
// new sighashes for witness transactions (BIP0143).
func WriteTxOut(w io.Writer, pver uint32, version int32, to *wire.TxOut) error {
	err := binarySerializer.PutUint64(w, littleEndian, uint64(to.Value))
	if err != nil {
		return err
	}

	return WriteVarBytes(w, pver, to.PkScript)
}

// writeTxIn encodes ti to the bitcoin protocol encoding for a transaction
// input (TxIn) to w.
func writeTxIn(w io.Writer, pver uint32, version int32, ti *wire.TxIn) error {
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

// writeOutPoint encodes op to the bitcoin protocol encoding for an OutPoint
// to w.
func writeOutPoint(w io.Writer, pver uint32, version int32, op *wire.OutPoint) error {
	_, err := w.Write(op.Hash[:])
	if err != nil {
		return err
	}

	return binarySerializer.PutUint32(w, littleEndian, op.Index)
}

// writeTxWitness encodes the bitcoin protocol encoding for a transaction
// input's witness into to w.
func writeTxWitness(w io.Writer, pver uint32, version int32, wit [][]byte) error {
	err := WriteVarInt(w, pver, uint64(len(wit)))
	if err != nil {
		return err
	}
	for _, item := range wit {
		err = WriteVarBytes(w, pver, item)
		if err != nil {
			return err
		}
	}
	return nil
}

func (msg *MsgTx) ZecSerialize(w io.Writer) error {
	return msg.ZecEncode(w, 0, wire.BaseEncoding)
}

func (msg *MsgTx) ZecDeserialize(r io.Reader) error {
	return msg.zecDecode(r, 0, wire.BaseEncoding)
}

func ZecTxFromHex(raw string) (*MsgTx, error) {
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	mtx := &MsgTx{MsgTx: wire.NewMsgTx(3)} // 版本会在解码时覆盖为 3 或 4
	if err := mtx.ZecDeserialize(bytes.NewReader(b)); err != nil {
		return nil, err
	}
	return mtx, nil
}

func (msg *MsgTx) ZecToHex() (string, error) {
	var buf bytes.Buffer
	if err := msg.ZecSerialize(&buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

func (msg *MsgTx) zecDecode(r io.Reader, _ uint32, enc wire.MessageEncoding) error {
	var verWithFlag uint32
	if err := binary.Read(r, binary.LittleEndian, &verWithFlag); err != nil {
		return err
	}
	fOverwintered := (verWithFlag >> 31) == 1
	msg.Version = int32(verWithFlag & 0x7fffffff)
	if !fOverwintered {
		return fmt.Errorf("not overwintered tx (expect v3/v4)")
	}

	var vgid uint32
	if err := binary.Read(r, binary.LittleEndian, &vgid); err != nil {
		return err
	}
	switch vgid {
	case versionOverwinterGroupID:
		msg.Version = versionOverwinter
	case versionSaplingGroupID:
		msg.Version = versionSapling
	default:
		return fmt.Errorf("unknown versionGroupID: 0x%x", vgid)
	}

	nIn, err := ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	msg.TxIn = make([]*wire.TxIn, 0, nIn)
	for i := uint64(0); i < nIn; i++ {
		ti, err := readTxInZec(r)
		if err != nil {
			return err
		}
		msg.AddTxIn(ti)
	}

	nOut, err := ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	msg.TxOut = make([]*wire.TxOut, 0, nOut)
	for i := uint64(0); i < nOut; i++ {
		to, err := readTxOutZec(r)
		if err != nil {
			return err
		}
		msg.AddTxOut(to)
	}

	if err := binary.Read(r, binary.LittleEndian, &msg.LockTime); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &msg.ExpiryHeight); err != nil {
		return err
	}

	if msg.Version == versionSapling {
		var vb uint64
		if err := binary.Read(r, binary.LittleEndian, &vb); err != nil {
			return err
		}
		ns, err := ReadVarInt(r, 0)
		if err != nil {
			return err
		}
		no, err := ReadVarInt(r, 0)
		if err != nil {
			return err
		}
		if ns != 0 || no != 0 {
			return fmt.Errorf("non-transparent sapling fields present: nShieldedSpend=%d nShieldedOutput=%d", ns, no)
		}
	}

	js, err := ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if js != 0 {
		return fmt.Errorf("non-transparent sprout joinsplits present: n=%d", js)
	}

	return nil
}

func readTxInZec(r io.Reader) (*wire.TxIn, error) {
	var op wire.OutPoint
	if _, err := io.ReadFull(r, op.Hash[:]); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &op.Index); err != nil {
		return nil, err
	}
	sig, err := ReadVarBytes(r, 0, LocalMaxTxInPayload)
	if err != nil {
		return nil, err
	}
	var seq uint32
	if err := binary.Read(r, binary.LittleEndian, &seq); err != nil {
		return nil, err
	}
	return &wire.TxIn{
		PreviousOutPoint: op,
		SignatureScript:  sig,
		Sequence:         seq,
	}, nil
}

func readTxOutZec(r io.Reader) (*wire.TxOut, error) {
	var val uint64
	if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
		return nil, err
	}
	pk, err := ReadVarBytes(r, 0, LocalMaxTxOutPayload)
	if err != nil {
		return nil, err
	}
	return &wire.TxOut{
		Value:    int64(val),
		PkScript: pk,
	}, nil
}

const MaxScriptSize = 10000

const (
	LocalMaxTxInPayload  = MaxScriptSize
	LocalMaxTxOutPayload = MaxScriptSize
)

func ReadVarInt(r io.Reader, _ uint32) (uint64, error) {
	var p [1]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return 0, err
	}
	switch p[0] {
	case 0xff:
		var v uint64
		if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
			return 0, err
		}
		if v <= 0xffffffff {
			return 0, fmt.Errorf("non-canonical varint: 0xff for <= 0xffffffff")
		}
		return v, nil
	case 0xfe:
		var v uint32
		if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
			return 0, err
		}
		if v <= 0xffff {
			return 0, fmt.Errorf("non-canonical varint: 0xfe for <= 0xffff")
		}
		return uint64(v), nil
	case 0xfd:
		var v uint16
		if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
			return 0, err
		}
		if v < 0xfd {
			return 0, fmt.Errorf("non-canonical varint: 0xfd for < 0xfd")
		}
		return uint64(v), nil
	default:
		return uint64(p[0]), nil
	}
}

func ReadVarBytes(r io.Reader, pver uint32, max int) ([]byte, error) {
	l, err := ReadVarInt(r, pver)
	if err != nil {
		return nil, err
	}
	if l > uint64(max) {
		return nil, fmt.Errorf("varbytes too large: %d > %d", l, max)
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
