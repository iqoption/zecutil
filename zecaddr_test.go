package zecutil

import (
	"reflect"
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


func TestPkHashFromAddress_T1AndTexSame(t *testing.T) {
	//（mainnet）
	t1 := "t1XtsHnj4Ev6CWC3HfJ7Xu3GkEP7SCy8hxV"
	tex := "tex1n88w7cmg9uzdluuct3krjqlkcxyz8tku8sq40s"

	netParam := &chaincfg.Params{
		Name: "mainnet",
	}

	// 1. use PkHashFromAddress for pkHash
	pkhT1, err := PkHashFromAddress(t1, netParam)
	if err != nil {
		t.Fatalf("PkHashFromAddress(t1) error: %v", err)
	}

	pkhTex, err := PkHashFromAddress(tex, netParam)
	if err != nil {
		t.Fatalf("PkHashFromAddress(tex) error: %v", err)
	}

	if !reflect.DeepEqual(pkhT1, pkhTex) {
		t.Fatalf("pkHash not equal: t1=%x tex=%x", pkhT1, pkhTex)
	}

	// 2. use DecodeAddress to check  ScriptAddress
	addrT1, err := DecodeAddress(t1, netParam.Name)
	if err != nil {
		t.Fatalf("DecodeAddress(t1) error: %v", err)
	}
	addrTex, err := DecodeAddress(tex, netParam.Name)
	if err != nil {
		t.Fatalf("DecodeAddress(tex) error: %v", err)
	}

	z1, ok1 := addrT1.(*ZecAddressPubKeyHash)
	if !ok1 {
		t.Fatalf("DecodeAddress(t1) type = %T, want *ZecAddressPubKeyHash", addrT1)
	}
	z2, ok2 := addrTex.(*ZecAddressPubKeyHash)
	if !ok2 {
		t.Fatalf("DecodeAddress(tex) type = %T, want *ZecAddressPubKeyHash", addrTex)
	}

	if !reflect.DeepEqual(z1.ScriptAddress(), z2.ScriptAddress()) {
		t.Fatalf("ScriptAddress not equal: t1=%x tex=%x", z1.ScriptAddress(), z2.ScriptAddress())
	}
}
