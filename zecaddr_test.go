package zecutil

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/stretchr/testify/require"

	"github.com/btcsuite/btcd/chaincfg"
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

func TestDecodeTexAndT1SameHash(t *testing.T) {
	t1 := "t1XtsHnj4Ev6CWC3HfJ7Xu3GkEP7SCy8hxV"
	tex := "tex1n88w7cmg9uzdluuct3krjqlkcxyz8tku8sq40s"

	addr1, err := DecodeAddress(t1, "mainnet")
	require.NoError(t, err)

	addr2, err := DecodeAddress(tex, "mainnet")
	require.NoError(t, err)

	a1 := addr1.(*ZecAddressPubKeyHash)
	a2 := addr2.(*ZecAddressPubKeyHash)

	require.Equal(t, a1.hash, a2.hash)
}
