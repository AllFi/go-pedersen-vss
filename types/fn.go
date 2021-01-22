package types

import (
	"crypto/rand"
	"math/big"

	"github.com/ing-bank/zkrp/crypto/p256"
)

// Fn represents an element of the field defined by the prime N, where N is the
// order of the elliptic curve group secp256k1.
type Fn struct {
	*big.Int
}

func NewFn() Fn {
	return Fn{big.NewInt(0)}
}

func RandomFn() Fn {
	fn, _ := rand.Int(rand.Reader, p256.CURVE.N)
	return Fn{fn}
}

func (fn *Fn) Copy() Fn {
	copy := Fn{new(big.Int)}
	copy.Int.Set(fn.Int)
	return copy
}

func (fn *Fn) IsZero() bool {
	return fn.Cmp(big.NewInt(0)) == 0
}

func (fn *Fn) Mul(a *Fn, b *Fn) {
	fn.Int = fn.Int.Mul(a.Int, b.Int)
}

func (fn *Fn) Add(a *Fn, b *Fn) {
	fn.Int = fn.Int.Add(a.Int, b.Int)
}
