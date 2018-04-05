package zecutil

import (
	"testing"
	"bytes"
	"fmt"
	"encoding/hex"

	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/btcec"

)

const (
	testWif = "cPAM37GAZpXkS7YRJGRggyKrGk7qEZKjNkXvq9gcgzjYaghrjGhg"
	senderAddr = "tmRfZVuDK6gVDfwJie1zepKjAELqaGAgWZr"
)

var netParams = &chaincfg.Params{
	Name: "test",
}

func TestSign(t *testing.T)  {
	var (
		wif *btcutil.WIF
		err error
	)

	if wif, err = btcutil.DecodeWIF(testWif); err != nil {
		t.Fatal("can't parse wif")
	}

	var ph *chainhash.Hash
	if ph, err = chainhash.NewHashFromStr(
		"e446be46fe7b44de1baf3b451227da8bbabc96b27ba17940ad759a8b6e61151c",
		); err != nil {
		t.Fatal(err)
	}

	newTx := wire.NewMsgTx(3)
	txIn := wire.NewTxIn(wire.NewOutPoint(ph, 1, ), nil, nil)
	newTx.AddTxIn(txIn)

	type receiver struct {
		addr string
		amount int64
	}

	receivers := []receiver{
		{"tmF834qorixnCV18bVrkM8WN1Xasy5eXcZV", 200000},
		{senderAddr, 299750000},
	}

	for _, receiver := range receivers {
		receiverAddr, err := btcutil.DecodeAddress(receiver.addr, netParams)
		if err != nil {
			t.Fatal(err)
		}

		receiverPkScript, err := txscript.PayToAddrScript(receiverAddr)
		if err != nil {
			t.Fatal(err)
		}

		txOut := wire.NewTxOut(receiver.amount, receiverPkScript)
		newTx.AddTxOut(txOut)
	}


	zecTx := &MsgTx{
		MsgTx:        newTx,
		ExpiryHeight: 215039,
	}

	var prevTxScript []byte
	if prevTxScript, err = hex.DecodeString("76a914aefaebf9c83deba2ec76e080e2cec850dec161b188ac"); err != nil {
		t.Fatal(err)
	}
	sigScript, err := SignTxOutput(
		netParams,
		zecTx,
		0,
		prevTxScript,
		txscript.SigHashAll,
		txscript.KeyClosure(func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
			return wif.PrivKey, wif.CompressPubKey, nil
		}),
		nil,
		nil,
		0)
	if err != nil {
		t.Fatal(err)
	}
	txIn.SignatureScript = sigScript

	var buf bytes.Buffer
	if err = zecTx.BtcEncode(&buf, 0, wire.BaseEncoding); err != nil {
		t.Fatal(err)
	}

	final := "030000807082c403011c15616e8b9a75ad4079a17bb296bcba8bda2712453baf1bde447bfe46be46e4010000006b48304502210093f8edae9784fee695d5ac5f84b4217084345a53c31c9e1e8e2a183ebe15cace02206872d90d0af77a4a4c18b761cf511e4583597ee5503e0e82e491da0f1a4377ed012103362327ee808f5961d26ef1a431386d6190638d67c14aa0e78e2eba1b58870cc0ffffffff02400d0300000000001976a9143b535da0ba90dad71ea005cccfe3cca47d746b3a88ac70d2dd11000000001976a914aefaebf9c83deba2ec76e080e2cec850dec161b188ac00000000ff47030000"

	if fmt.Sprintf("%x", buf.Bytes()) != final {
		t.Fatal("incorrect sig")
	}
}