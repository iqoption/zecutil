# zecutil

Zcash Utilities

Contains the zcash signing algorithm and some protocol configuration. Forked from [https://github.com/cpacia/bchutil/](https://github.com/cpacia/bchutil/)

## Supports

* [Overwinter](https://z.cash/upgrade/overwinter.html) network upgrade for Zcash. Not support joinsplits.
* [Sapling](https://z.cash/upgrade/sapling/) network upgrade for Zcash.

## How to use
- First install the dependencies

```bash
go get github.com/iqoption/zecutil
go get github.com/btcsuite/btcd
go get github.com/btcsuite/btcutil
```

- Open [example.go](./example.go) and update your wallet details. You can use `http://zcashnetwork.info/api/addr/<your_address>/utxo` to get the list of UTXOs

- Build and run the binary

```bash
go build example.go
./example
```

- You can broadcast your transaction using [this form](http://zcashnetwork.info/tx/send)