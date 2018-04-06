package zecutil

import (
	"crypto/sha256"
	"errors"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

var Prefixes = map[string][]byte{
	"main":    {0x1C, 0xB8},
	"test":    {0x1D, 0x25},
	"regtest": {0x1D, 0x25},
}

type ZecAddressPubKeyHash struct {
	hash   [ripemd160.Size]byte
	prefix string
}

// Encode pubHash to zec address
func Encode(pkHash []byte, net *chaincfg.Params) (_ string, err error) {
	if _, ok := Prefixes[net.Name]; !ok {
		return "", errors.New("unknown network parameters")
	}

	var addrPubKey *btcutil.AddressPubKey
	if addrPubKey, err = btcutil.NewAddressPubKey(pkHash, net); err != nil {
		return "", err
	}

	return EncodeHash(btcutil.Hash160(addrPubKey.ScriptAddress())[:ripemd160.Size], net)
}

func EncodeHash(addrHash []byte, net *chaincfg.Params) (_ string, err error) {
	if _, ok := Prefixes[net.Name]; !ok {
		return "", errors.New("unknown network parameters")
	}

	if len(addrHash) != ripemd160.Size {
		return "", errors.New("incorrect hash length")
	}

	var (
		body  = append(Prefixes[net.Name], addrHash[:ripemd160.Size]...)
		chk   = addrChecksum(body)
		cksum [4]byte
	)

	copy(cksum[:], chk[:4])

	return base58.Encode(append(body, cksum[:]...)), nil
}

// DecodeAddress zec address string
func DecodeAddress(address string) (btcutil.Address, error) {
	var decoded = base58.Decode(address)
	if len(decoded) < 5 {
		return nil, base58.ErrInvalidFormat
	}

	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])

	if addrChecksum(decoded[:len(decoded)-4]) != cksum {
		return nil, base58.ErrChecksum
	}

	if len(decoded)-6 != ripemd160.Size {
		return nil, errors.New("incorrect payload len")
	}

	addr := &ZecAddressPubKeyHash{}
	copy(addr.hash[:], decoded[2:len(decoded)-4])

	for name, p := range Prefixes {
		if p[0] == decoded[0] && p[1] == decoded[1] {
			addr.prefix = name
			break
		}
	}

	return addr, nil
}

// EncodeAddress returns the string encoding of a pay-to-pubkey-hash
// address.  Part of the Address interface.
func (a *ZecAddressPubKeyHash) EncodeAddress() (addr string) {
	addr, _ = EncodeHash(a.hash[:], &chaincfg.Params{Name: a.prefix})
	return addr
}

// ScriptAddress returns the bytes to be included in a txout script to pay
// to a pubkey hash.  Part of the Address interface.
func (a *ZecAddressPubKeyHash) ScriptAddress() []byte {
	return a.hash[:]
}

// IsForNet returns whether or not the pay-to-pubkey-hash address is associated
// with the passed bitcoin cash network.
func (a *ZecAddressPubKeyHash) IsForNet(net *chaincfg.Params) bool {
	_, ok := Prefixes[net.Name]
	if !ok {
		return false
	}
	return a.prefix == net.Name
}

// String returns a human-readable string for the pay-to-pubkey-hash address.
// This is equivalent to calling EncodeAddress, but is provided so the type can
// be used as a fmt.Stringer.
func (a *ZecAddressPubKeyHash) String() string {
	return a.EncodeAddress()
}

func addrChecksum(input []byte) (cksum [4]byte) {
	var (
		h  = sha256.Sum256(input)
		h2 = sha256.Sum256(h[:])
	)

	copy(cksum[:], h2[:4])

	return
}
