package zecutil

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	testWif    = "cPAM37GAZpXkS7YRJGRggyKrGk7qEZKjNkXvq9gcgzjYaghrjGhg"
	senderAddr = "tmRfZVuDK6gVDfwJie1zepKjAELqaGAgWZr"
)

var netParams = &chaincfg.Params{
	Name: "test",
}

func TestSign(t *testing.T) {
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
	txIn := wire.NewTxIn(wire.NewOutPoint(ph, 1), nil, nil)
	newTx.AddTxIn(txIn)

	type receiver struct {
		addr   string
		amount int64
	}

	receivers := []receiver{
		{"tmF834qorixnCV18bVrkM8WN1Xasy5eXcZV", 200000},
		{senderAddr, 299750000},
	}

	for _, receiver := range receivers {
		decoded := base58.Decode(receiver.addr)
		var addr *btcutil.AddressPubKeyHash
		if addr, err = btcutil.NewAddressPubKeyHash(decoded[2:len(decoded)-4], netParams); err != nil {
			t.Fatal(err)
		}

		if err != nil {
			t.Fatal(err)
		}

		receiverPkScript, err := txscript.PayToAddrScript(addr)
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
	if err = zecTx.ZecEncode(&buf, 0, wire.BaseEncoding); err != nil {
		t.Fatal(err)
	}

	final := "030000807082c403011c15616e8b9a75ad4079a17bb296bcba8bda2712453baf1bde447bfe46be46e4010000006b48304502210093f8edae9784fee695d5ac5f84b4217084345a53c31c9e1e8e2a183ebe15cace02206872d90d0af77a4a4c18b761cf511e4583597ee5503e0e82e491da0f1a4377ed012103362327ee808f5961d26ef1a431386d6190638d67c14aa0e78e2eba1b58870cc0ffffffff02400d0300000000001976a9143b535da0ba90dad71ea005cccfe3cca47d746b3a88ac70d2dd11000000001976a914aefaebf9c83deba2ec76e080e2cec850dec161b188ac00000000ff47030000"
	if fmt.Sprintf("%x", buf.Bytes()) != final {
		t.Fatal("incorrect sig")
	}
}

func TestHash(t *testing.T) {
	var (
		err error
		ph  *chainhash.Hash
	)

	if ph, err = chainhash.NewHashFromStr(
		"669f631ce20574fc33cd3e810bac941aff7b661e21ba4769e01bfd68509fc4e6",
	); err != nil {
		t.Fatal(err)
	}

	var ss []byte
	if ss, err = hex.DecodeString("4730440220307f094227b2e9b130ed9ee5fce75a043bb940681b204d11ca0c3c517f61f9f60220629e30a2f52e68e1ad6070be544bffc42bc439e7a8ea337f5974f6586222d69f012102da48746d58e04a4fb4ce381773cb6c8cedb71d009ebb740dea053c3e0f6cbf3c"); err != nil {
		t.Fatal(err)
	}

	newTx := wire.NewMsgTx(3)
	txIn := wire.NewTxIn(wire.NewOutPoint(ph, 1), ss, nil)
	newTx.AddTxIn(txIn)

	decoded := base58.Decode("tmHuu9Z7m5W7PcT4orLEANwnHKrB2aDfx5C")
	var addr *btcutil.AddressPubKeyHash
	if addr, err = btcutil.NewAddressPubKeyHash(decoded[2:len(decoded)-4], netParams); err != nil {
		t.Fatal(err)
	}

	pa, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	newTx.AddTxOut(wire.NewTxOut(299999742, pa))

	zecTx := &MsgTx{
		MsgTx:        newTx,
		ExpiryHeight: 219152,
	}

	expected := "65282283bfbb131106932683d567c5b8de16bbb9186d22c5bb0d26c9e3fcb096"
	if zecTx.TxHash().String() != expected {
		t.Fatal("Incorrect hash", "expected", expected, "got", zecTx.TxHash().String())
	}
}
