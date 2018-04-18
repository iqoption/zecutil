package zecutil

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

func TestEncode(t *testing.T) {
	var (
		wif *btcutil.WIF
		err error
	)

	if wif, err = btcutil.DecodeWIF(testWif); err != nil {
		t.Fatal("can't parse wif")
	}

	var encodedAddr string
	encodedAddr, err = Encode(wif.PrivKey.PubKey().SerializeCompressed(), &chaincfg.Params{
		Name: "testnet3",
	})

	if err != nil {
		t.Fatal(err)
	}

	expectedAddr := senderAddr
	if expectedAddr != encodedAddr {
		t.Fatal("incorrect encode", "expected", expectedAddr, "got", encodedAddr)
	}

	_, err = Encode(wif.PrivKey.PubKey().SerializeCompressed(), &chaincfg.Params{
		Name: "dummy",
	})

	if err == nil {
		t.Fatal("incorect error, got nil")
	}
}

func TestDecode(t *testing.T) {
	addrs := []string{
		"tmF834qorixnCV18bVrkM8WN1Xasy5eXcZV",
		"tmRfZVuDK6gVDfwJie1zepKjAELqaGAgWZr",
	}

	for _, addr := range addrs {
		a, err := DecodeAddress(addr, "testnet3")
		if err != nil {
			t.Fatal("got err", "expected nil", "got", err)
		}

		if !a.IsForNet(&chaincfg.Params{Name: "testnet3"}) {
			t.Fatal("incorrect net")
		}

		if a.EncodeAddress() != addr {
			t.Fatal("incorrect decode")
		}
	}
}
