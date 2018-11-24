package zecutil

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/codahale/blake2"
)

// blake2bHash Zcash hash func
func blake2bHash(data, key []byte) (h chainhash.Hash, err error) {
	bHash := blake2.New(&blake2.Config{
		Size:     32,
		Personal: key,
	})

	if _, err = bHash.Write(data); err != nil {
		return h, err
	}

	err = (&h).SetBytes(bHash.Sum(nil))
	return h, err
}
