package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	"github.com/iqoption/zecutil"
)

// Input represents UTXO
type Input struct {
	Amount        int64
	Confirmations uint64
	Script        string
	Txid          string
	Txindex       uint32
}

// Output represents receiver's address and the amount to be sent
type Output struct {
	Address string
	Amount  int64
}

func main() {
	// 5235736f9a7cac938d870f870f3e66c787107b9f4986336d736f0b03c9eb59ae

	netParams := &chaincfg.MainNetParams
	txVersion := 4

	inputs := []Input{
		{
			Amount:        380000,
			Confirmations: 1,
			Script:        "76a914b4092afd05b0d3f8cf5836067f8e53d8bc4034c888ac",
			Txid:          "5606cd664ad26f3643c7041fca5ddac47fffe7e9675e87b8e7d4b84d562ae215",
			Txindex:       0,
		},
		{
			Amount:        3980000,
			Confirmations: 13,
			Script:        "76a914b4092afd05b0d3f8cf5836067f8e53d8bc4034c888ac",
			Txid:          "ea1d3dc7ac16f93f90e6b8030222471e36f0d0a27e3385ccfbbc6e3513126de6",
			Txindex:       0,
		},
	}
	outputs := []Output{
		{
			Address: "t1TDusBKXRgyruL9wHgQt9vQUW1PwdWAAZo",
			Amount:  4350000,
		},
	}
	pkey := "L247RjuxKEFpkj3FmfgRGQsioLVkMoVvJk2B7nFhxTyrrm56N2RL"

	var (
		privateKey *btcutil.WIF
		err        error
	)

	if privateKey, err = btcutil.DecodeWIF(pkey); err != nil {
		panic("can't parse wif")
	}
	newTx := wire.NewMsgTx(int32(txVersion))

	for _, receiver := range outputs {
		decoded := base58.Decode(receiver.Address)
		var addr *btcutil.AddressPubKeyHash
		if addr, err = btcutil.NewAddressPubKeyHash(decoded[2:len(decoded)-4], netParams); err != nil {
			panic(err)
		}

		receiverPkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			panic(err)
		}
		txOut := wire.NewTxOut(receiver.Amount, receiverPkScript)
		newTx.AddTxOut(txOut)

	}
	for _, in := range inputs {
		var ph *chainhash.Hash
		if ph, err = chainhash.NewHashFromStr(in.Txid); err != nil {
			panic(err)
		}
		txIn := wire.NewTxIn(wire.NewOutPoint(ph, in.Txindex), nil, nil)
		newTx.AddTxIn(txIn)
	}

	zecTx := &zecutil.MsgTx{
		MsgTx: newTx,
		// https://github.com/zcash/zcash/blob/0f091f228cdb1793a10ea59f82b7c7f0b93edb7a/src/consensus/consensus.h#L31
		ExpiryHeight: 500000000 - 1,
	}

	for idx, in := range inputs {
		var prevTxScript []byte
		if prevTxScript, err = hex.DecodeString(in.Script); err != nil {
			panic(err)
		}
		sigScript, err := zecutil.SignTxOutput(
			netParams,
			zecTx,
			idx,
			prevTxScript,
			txscript.SigHashAll,
			txscript.KeyClosure(func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
				return privateKey.PrivKey, privateKey.CompressPubKey, nil
			}),
			nil,
			nil,
			in.Amount)
		if err != nil {
			panic(err)
		}
		newTx.TxIn[idx].SignatureScript = sigScript
	}

	var buf bytes.Buffer
	if err = zecTx.ZecEncode(&buf, 0, wire.BaseEncoding); err != nil {
		panic(err)
	}
	fmt.Printf("Tx raw: %x\n\n", buf.Bytes())
	fmt.Printf("Tx Hash: %s\n", zecTx.TxHash().String())
}
