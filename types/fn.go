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

// NewFn returns a new feild element
func NewFn() Fn {
	return Fn{big.NewInt(0)}
}

// RandomFn returns a random field element
func RandomFn() Fn {
	fn, _ := rand.Int(rand.Reader, p256.CURVE.N)
	return Fn{fn}
}

// Copy returns copy of the field element
func (fn *Fn) Copy() Fn {
	copy := Fn{new(big.Int)}
	copy.Int.Set(fn.Int)
	return copy
}

// IsZero returns true if the field element is zero and false otherwise.
func (fn *Fn) IsZero() bool {
	return fn.Cmp(big.NewInt(0)) == 0
}

// Add computes the addition of the two field elements and stores the result in
// the receiver.
func (fn *Fn) Add(a *Fn, b *Fn) {
	fn.Int = fn.Int.Add(a.Int, b.Int)
	fn.Int.Mod(fn.Int, p256.CURVE.N)
}

// Mul computes the multiplication of the two field elements and stores the
// result in the receiver.
func (fn *Fn) Mul(a *Fn, b *Fn) {
	fn.Int = fn.Int.Mul(a.Int, b.Int)
	fn.Int.Mod(fn.Int, p256.CURVE.N)
}

// Eq returns true if the two field elements are equal, and false otherwise.
func (fn *Fn) Eq(other *Fn) bool {
	return fn.Int.Cmp(other.Int) == 0
}

// Negate computes the additive inverse of the given field element and stores
// the result in the receiver.
func (fn *Fn) Negate(a *Fn) {
	fn.Sub(p256.CURVE.N, a.Int)
}

// Inverse computes the multiplicative inverse of the given field element and
// stores the result in the receiver.
func (fn *Fn) Inverse(a *Fn) {
	fn.ModInverse(a.Int, p256.CURVE.N)
}
