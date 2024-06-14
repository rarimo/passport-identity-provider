package zknullifiers

// This is an implementation of the interface for merkle tree building. It hashes with TRULY
// compatible Poseidon hash function.

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

const _hashlength = 32

type Poseidon struct{}

func NewPoseidon() *Poseidon {
	return &Poseidon{}
}

func (*Poseidon) Hash(data ...[]byte) []byte {
	var hash *big.Int
	if len(data) == 1 {
		hash = mustPoseidon(new(big.Int).SetBytes(data[0]))
	} else {
		bigData := make([]*big.Int, len(data))
		for i, d := range data {
			bigData[i] = new(big.Int).SetBytes(d)
		}
		hash = mustPoseidon(bigData...)
	}

	return hash.Bytes()
}

func (*Poseidon) HashLength() int {
	return _hashlength
}

func (*Poseidon) HashName() string {
	return "poseidon"
}

func mustPoseidon(elements ...*big.Int) *big.Int {
	hash, _ := poseidon.Hash(elements)
	return hash
}
