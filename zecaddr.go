package zecutil

import (
	"crypto/sha256"
	"errors"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

type ChainParams struct {
	PubHashPrefixes    []byte
	ScriptHashPrefixes []byte
}

var (
	MainNet = ChainParams{
		PubHashPrefixes:    []byte{0x1C, 0xB8},
		ScriptHashPrefixes: []byte{0x1C, 0xBD},
	}

	TestNet3 = ChainParams{
		PubHashPrefixes:    []byte{0x1D, 0x25},
		ScriptHashPrefixes: []byte{0x1C, 0xBA},
	}

	NetList = map[string]ChainParams{
		"mainnet":  MainNet,
		"testnet3": TestNet3,
		"regtest":  TestNet3,
	}
)

type ZecAddressScriptHash struct {
	hash   [ripemd160.Size]byte
	prefix string
}

type ZecAddressPubKeyHash struct {
	hash   [ripemd160.Size]byte
	prefix string
}

func NewAddressPubKeyHash(hash [ripemd160.Size]byte, prefix string) *ZecAddressPubKeyHash {
	return &ZecAddressPubKeyHash{hash, prefix}
}

// Encode pubHash to zec address
func Encode(pkHash []byte, net *chaincfg.Params) (_ string, err error) {
	if _, ok := NetList[net.Name]; !ok {
		return "", errors.New("unknown network parameters")
	}

	var addrPubKey *btcutil.AddressPubKey
	if addrPubKey, err = btcutil.NewAddressPubKey(pkHash, net); err != nil {
		return "", err
	}

	return EncodeHash(btcutil.Hash160(addrPubKey.ScriptAddress())[:ripemd160.Size], NetList[net.Name].PubHashPrefixes)
}

func EncodeHash(addrHash []byte, prefix []byte) (_ string, err error) {
	if len(addrHash) != ripemd160.Size {
		return "", errors.New("incorrect hash length")
	}

	var (
		body  = append(prefix, addrHash[:ripemd160.Size]...)
		chk   = addrChecksum(body)
		cksum [4]byte
	)

	copy(cksum[:], chk[:4])

	return base58.Encode(append(body, cksum[:]...)), nil
}

// DecodeAddress zec address string
func DecodeAddress(address string, netName string) (btcutil.Address, error) {
	var (
		net ChainParams
		ok  bool
	)

	if net, ok = NetList[netName]; !ok {
		return nil, errors.New("unknown net")
	}

	var decoded = base58.Decode(address)
	if len(decoded) != 26 {
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

	switch {
	case net.PubHashPrefixes[0] == decoded[0] && net.PubHashPrefixes[1] == decoded[1]:
		addr := &ZecAddressPubKeyHash{prefix: netName}
		copy(addr.hash[:], decoded[2:len(decoded)-4])
		return addr, nil
	case net.ScriptHashPrefixes[0] == decoded[0] && net.ScriptHashPrefixes[1] == decoded[1]:
		addr := &ZecAddressScriptHash{prefix: netName}
		copy(addr.hash[:], decoded[2:len(decoded)-4])
		return addr, nil
	}

	return nil, errors.New("unknown address")
}

// EncodeAddress returns the string encoding of a pay-to-pubkey-hash
// address.  Part of the Address interface.
func (a *ZecAddressPubKeyHash) EncodeAddress() (addr string) {
	addr, _ = EncodeHash(a.hash[:], NetList[a.prefix].PubHashPrefixes)
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
	_, ok := NetList[net.Name]
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

// EncodeAddress returns the string encoding of a pay-to-pubkey-hash
// address.  Part of the Address interface.
func (a *ZecAddressScriptHash) EncodeAddress() (addr string) {
	addr, _ = EncodeHash(a.hash[:], NetList[a.prefix].ScriptHashPrefixes)
	return addr
}

// ScriptAddress returns the bytes to be included in a txout script to pay
// to a pubkey hash.  Part of the Address interface.
func (a *ZecAddressScriptHash) ScriptAddress() []byte {
	return a.hash[:]
}

// IsForNet returns whether or not the pay-to-pubkey-hash address is associated
// with the passed bitcoin cash network.
func (a *ZecAddressScriptHash) IsForNet(net *chaincfg.Params) bool {
	_, ok := NetList[net.Name]
	if !ok {
		return false
	}
	return a.prefix == net.Name
}

// String returns a human-readable string for the pay-to-pubkey-hash address.
// This is equivalent to calling EncodeAddress, but is provided so the type can
// be used as a fmt.Stringer.
func (a *ZecAddressScriptHash) String() string {
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
