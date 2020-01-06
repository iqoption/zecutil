package zecutil

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/dchest/blake2b"
)

// blake2bHash zcash hash func
func blake2bHash(data, key []byte) (h chainhash.Hash, err error) {
	bHash, err := blake2b.New(&blake2b.Config{Size: 32, Person: key})
	if err != nil {
		return h, err
	}

	if _, err = bHash.Write(data); err != nil {
		return h, err
	}

	err = (&h).SetBytes(bHash.Sum(nil))
	return h, err
}
