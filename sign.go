package zecutil

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

type upgradeParam struct {
	ActivationHeight uint32
	BranchID         []byte
}

const (
	sigHashMask    = 0x1f
	blake2BSigHash = "ZcashSigHash"
)

const (
	versionOverwinter int32 = 3
	versionSapling          = 4
)

const (
	versionOverwinterGroupID uint32 = 0x3C48270
	versionSaplingGroupID           = 0x892f2085
)

// https://github.com/zcash/zcash/blob/89f5ee5dec3fdfd70202baeaf74f09fa32bfb1a8/src/chainparams.cpp#L99
// https://github.com/zcash/zcash/blob/master/src/consensus/upgrades.cpp#L11
// activation levels are used for testnet because mainnet is already updated
// TODO: need implement own complete chain params and use them
var upgradeParams = []upgradeParam{
	{0, []byte{0x00, 0x00, 0x00, 0x00}},
	{207500, []byte{0x19, 0x1B, 0xA8, 0x5B}},
	{280000, []byte{0xBB, 0x09, 0xB8, 0x76}},
	{653600, []byte{0x60, 0x0E, 0xB4, 0x2B}},
}

// RawTxInSignature returns the serialized ECDSA signature for the input idx of
// the given transaction, with hashType appended to it.
func RawTxInSignature(
	tx *MsgTx,
	idx int,
	subScript []byte,
	hashType txscript.SigHashType,
	key *btcec.PrivateKey,
	amt int64,
) (_ []byte, err error) {
	var cache *txscript.TxSigHashes
	if cache, err = NewTxSigHashes(tx); err != nil {
		return nil, err
	}

	bHash, err := blake2bSignatureHash(subScript, cache, hashType, tx, idx, amt)
	if err != nil {
		return nil, err
	}

	signature, err := key.Sign(bHash)
	if err != nil {
		return nil, fmt.Errorf("cannot sign tx input: %s", err)
	}

	return append(signature.Serialize(), byte(hashType)), nil
}

// SignTxOutput for sign zec transactions inputs
func SignTxOutput(
	chainParams *chaincfg.Params,
	tx *MsgTx,
	idx int,
	pkScript []byte,
	hashType txscript.SigHashType,
	kdb txscript.KeyDB,
	sdb txscript.ScriptDB,
	previousScript []byte,
	amt int64,
) ([]byte, error) {
	sigScript, class, addresses, nrequired, err := sign(
		chainParams,
		tx,
		idx,
		pkScript,
		hashType,
		kdb,
		sdb,
		amt,
	)
	if err != nil {
		return nil, err
	}

	if class == txscript.ScriptHashTy {
		// TODO: keep the sub addressed and pass down to merge.
		realSigScript, _, _, _, err := sign(
			chainParams,
			tx,
			idx,
			sigScript,
			hashType,
			kdb,
			sdb,
			amt,
		)
		if err != nil {
			return nil, err
		}

		// Append the p2sh script as the last push in the script.
		builder := txscript.NewScriptBuilder()
		builder.AddOps(realSigScript)
		builder.AddData(sigScript)

		sigScript, _ = builder.Script()
		// TODO: keep a copy of the script for merging.
	}

	// Merge scripts. with any previous data, if any.
	mergedScript := mergeScripts(
		chainParams,
		tx,
		idx,
		pkScript,
		class,
		addresses,
		nrequired,
		sigScript,
		previousScript,
	)
	return mergedScript, nil
}

// sigHashKey return blake2b key by current height
func sigHashKey(activationHeight uint32) []byte {
	var i int
	for i = len(upgradeParams) - 1; i >= 0; i-- {
		if activationHeight >= upgradeParams[i].ActivationHeight {
			break
		}
	}

	return append([]byte(blake2BSigHash), upgradeParams[i].BranchID...)
}

// blake2bSignatureHash
func blake2bSignatureHash(
	subScript []byte,
	sigHashes *txscript.TxSigHashes,
	hashType txscript.SigHashType,
	tx *MsgTx,
	idx int,
	amt int64,
) (_ []byte, err error) {
	// As a sanity check, ensure the passed input index for the transaction
	// is valid.
	if idx > len(tx.TxIn)-1 {
		return nil, fmt.Errorf("blake2bSignatureHash error: idx %d but %d txins", idx, len(tx.TxIn))
	}

	// We'll utilize this buffer throughout to incrementally calculate
	// the signature hash for this transaction.
	var sigHash bytes.Buffer

	// << GetHeader
	// First write out, then encode the transaction's nVersion number. Zcash current nVersion = 3
	var bVersion [4]byte
	binary.LittleEndian.PutUint32(bVersion[:], uint32(tx.Version)|(1<<31))
	sigHash.Write(bVersion[:])

	var versionGroupID = versionOverwinterGroupID
	if tx.Version == versionSapling {
		versionGroupID = versionSaplingGroupID
	}

	// << nVersionGroupId
	// Version group ID
	var nVersion [4]byte
	binary.LittleEndian.PutUint32(nVersion[:], versionGroupID)
	sigHash.Write(nVersion[:])

	// Next write out the possibly pre-calculated hashes for the sequence
	// numbers of all inputs, and the hashes of the previous outs for all
	// outputs.
	var zeroHash chainhash.Hash

	// << hashPrevouts
	// If anyone can pay isn't active, then we can use the cached
	// hashPrevOuts, otherwise we just write zeroes for the prev outs.
	if hashType&txscript.SigHashAnyOneCanPay == 0 {
		sigHash.Write(sigHashes.HashPrevOuts[:])
	} else {
		sigHash.Write(zeroHash[:])
	}

	// << hashSequence
	// If the sighash isn't anyone can pay, single, or none, the use the
	// cached hash sequences, otherwise write all zeroes for the
	// hashSequence.
	if hashType&txscript.SigHashAnyOneCanPay == 0 &&
		hashType&sigHashMask != txscript.SigHashSingle &&
		hashType&sigHashMask != txscript.SigHashNone {
		sigHash.Write(sigHashes.HashSequence[:])
	} else {
		sigHash.Write(zeroHash[:])
	}

	// << hashOutputs
	// If the current signature mode isn't single, or none, then we can
	// re-use the pre-generated hashoutputs sighash fragment. Otherwise,
	// we'll serialize and add only the target output index to the signature
	// pre-image.
	if hashType&sigHashMask != txscript.SigHashSingle && hashType&sigHashMask != txscript.SigHashNone {
		sigHash.Write(sigHashes.HashOutputs[:])
	} else if hashType&sigHashMask == txscript.SigHashSingle && idx < len(tx.TxOut) {
		var (
			b bytes.Buffer
			h chainhash.Hash
		)
		if err = wire.WriteTxOut(&b, 0, 0, tx.TxOut[idx]); err != nil {
			return nil, err
		}

		if h, err = blake2bHash(b.Bytes(), []byte(outputsHashPersonalization)); err != nil {
			return nil, err
		}
		sigHash.Write(h.CloneBytes())
	} else {
		sigHash.Write(zeroHash[:])
	}

	// << hashJoinSplits
	sigHash.Write(zeroHash[:])

	// << hashShieldedSpends
	if tx.Version == versionSapling {
		sigHash.Write(zeroHash[:])
	}

	// << hashShieldedOutputs
	if tx.Version == versionSapling {
		sigHash.Write(zeroHash[:])
	}

	// << nLockTime
	var lockTime [4]byte
	binary.LittleEndian.PutUint32(lockTime[:], tx.LockTime)
	sigHash.Write(lockTime[:])

	// << nExpiryHeight
	var expiryTime [4]byte
	binary.LittleEndian.PutUint32(expiryTime[:], tx.ExpiryHeight)
	sigHash.Write(expiryTime[:])

	// << valueBalance
	if tx.Version == versionSapling {
		var valueBalance [8]byte
		binary.LittleEndian.PutUint64(valueBalance[:], 0)
		sigHash.Write(valueBalance[:])
	}

	// << nHashType
	var bHashType [4]byte
	binary.LittleEndian.PutUint32(bHashType[:], uint32(hashType))
	sigHash.Write(bHashType[:])

	if idx != math.MaxUint32 {
		// << prevout
		// Next, write the outpoint being spent.
		sigHash.Write(tx.TxIn[idx].PreviousOutPoint.Hash[:])
		var bIndex [4]byte
		binary.LittleEndian.PutUint32(bIndex[:], tx.TxIn[idx].PreviousOutPoint.Index)
		sigHash.Write(bIndex[:])

		// << scriptCode
		// For p2wsh outputs, and future outputs, the script code is the
		// original script, with all code separators removed, serialized
		// with a var int length prefix.
		// wire.WriteVarBytes(&sigHash, 0, subScript)
		if err = wire.WriteVarBytes(&sigHash, 0, subScript); err != nil {
			return nil, err
		}

		// << amount
		// Next, add the input amount, and sequence number of the input being
		// signed.
		if err = binary.Write(&sigHash, binary.LittleEndian, amt); err != nil {
			return nil, err
		}

		// << nSequence
		var bSequence [4]byte
		binary.LittleEndian.PutUint32(bSequence[:], tx.TxIn[idx].Sequence)
		sigHash.Write(bSequence[:])
	}

	var h chainhash.Hash
	if h, err = blake2bHash(sigHash.Bytes(), sigHashKey(tx.ExpiryHeight)); err != nil {
		return nil, err
	}

	return h.CloneBytes(), nil
}

func sign(
	chainParams *chaincfg.Params,
	tx *MsgTx,
	idx int,
	subScript []byte,
	hashType txscript.SigHashType,
	kdb txscript.KeyDB,
	sdb txscript.ScriptDB,
	amt int64,
) ([]byte, txscript.ScriptClass, []btcutil.Address, int, error) {
	class, addresses, nrequired, err := txscript.ExtractPkScriptAddrs(subScript, chainParams)
	if err != nil {
		return nil, txscript.NonStandardTy, nil, 0, err
	}

	switch class {
	case txscript.PubKeyHashTy:
		// look up key for address
		key, compressed, err := kdb.GetKey(addresses[0])
		if err != nil {
			return nil, class, nil, 0, err
		}

		script, err := SignatureScript(tx, idx, subScript, hashType, key, compressed, amt)
		if err != nil {
			return nil, class, nil, 0, err
		}

		return script, class, addresses, nrequired, nil
	case txscript.ScriptHashTy:
		script, err := sdb.GetScript(addresses[0])
		if err != nil {
			return nil, class, nil, 0, err
		}

		return script, class, addresses, nrequired, nil
	case txscript.MultiSigTy:
		script, _ := signMultiSig(tx, idx, subScript, hashType, addresses, nrequired, kdb, amt)
		return script, class, addresses, nrequired, nil
	default:
		return nil, class, nil, 0,
			errors.New("can't sign unknown transactions")
	}
}

// signMultiSig signs as many of the outputs in the provided multisig script as
// possible. It returns the generated script and a boolean if the script fulfils
// the contract (i.e. nrequired signatures are provided).  Since it is arguably
// legal to not be able to sign any of the outputs, no error is returned.
func signMultiSig(
	tx *MsgTx,
	idx int,
	subScript []byte,
	hashType txscript.SigHashType,
	addresses []btcutil.Address,
	nRequired int,
	kdb txscript.KeyDB,
	amt int64,
) ([]byte, bool) {
	// We start with a single OP_FALSE to work around the (now standard)
	// but in the reference implementation that causes a spurious pop at
	// the end of OP_CHECKMULTISIG.
	builder := txscript.NewScriptBuilder().AddOp(txscript.OP_FALSE)
	signed := 0
	for _, addr := range addresses {
		key, _, err := kdb.GetKey(addr)
		if err != nil {
			continue
		}
		sig, err := RawTxInSignature(tx, idx, subScript, hashType, key, amt)
		if err != nil {
			continue
		}

		builder.AddData(sig)
		signed++
		if signed == nRequired {
			break
		}

	}

	script, _ := builder.Script()
	return script, signed == nRequired
}

// SignatureScript generate transaction hash and sign it
func SignatureScript(
	tx *MsgTx,
	idx int,
	subscript []byte,
	hashType txscript.SigHashType,
	privKey *btcec.PrivateKey,
	compress bool,
	amount int64,
) ([]byte, error) {
	sig, err := RawTxInSignature(tx, idx, subscript, hashType, privKey, amount)
	if err != nil {
		return nil, err
	}

	pk := (*btcec.PublicKey)(&privKey.PublicKey)
	var pkData []byte
	if compress {
		pkData = pk.SerializeCompressed()
	} else {
		pkData = pk.SerializeUncompressed()
	}

	return txscript.NewScriptBuilder().AddData(sig).AddData(pkData).Script()
}

func mergeScripts(
	chainParams *chaincfg.Params,
	tx *MsgTx,
	idx int,
	pkScript []byte,
	class txscript.ScriptClass,
	addresses []btcutil.Address,
	nRequired int,
	sigScript,
	prevScript []byte,
) []byte {
	switch class {

	// It doesn't actually make sense to merge anything other than multiig
	// and scripthash (because it could contain multisig). Everything else
	// has either zero signature, can't be spent, or has a single signature
	// which is either present or not. The other two cases are handled
	// above. In the conflict case here we just assume the longest is
	// correct (this matches behaviour of the reference implementation).
	default:
		if len(sigScript) > len(prevScript) {
			return sigScript
		}

		return prevScript
	}
}
