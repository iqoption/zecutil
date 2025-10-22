package zecutil

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
)

func PayToAddrScript(addr btcutil.Address) ([]byte, error) {
	var script []byte
	var err error
	script, err = txscript.PayToAddrScript(addr)
	if err == nil {
		return script, nil
	}

	const nilAddrErrStr = "unable to generate payment script for nil address"
	switch addr := addr.(type) {
	case *ZecAddressPubKeyHash:
		if addr == nil {
			return nil, errors.New(nilAddrErrStr)
		}
		return payToPubKeyHashScript(addr.ScriptAddress())

	case *ZecAddressScriptHash:
		if addr == nil {
			return nil, errors.New(nilAddrErrStr)
		}
		return payToScriptHashScript(addr.ScriptAddress())
	}
	return nil, fmt.Errorf("unable to generate payment script for unsupported address type %T", addr)
}

// payToPubKeyHashScript creates a new script to pay a transaction
// output to a 20-byte pubkey hash. It is expected that the input is a valid
// hash.
func payToPubKeyHashScript(pubKeyHash []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).
		AddData(pubKeyHash).AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG).
		Script()
}

// payToScriptHashScript creates a new script to pay a transaction output to a
// script hash. It is expected that the input is a valid hash.
func payToScriptHashScript(scriptHash []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_HASH160).AddData(scriptHash).
		AddOp(txscript.OP_EQUAL).Script()
}
