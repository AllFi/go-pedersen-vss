package types

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
)

// the order of base point of secp256k1
var curveN *big.Int

func init() {
	var ok bool
	curveN, ok = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	if !ok {
		panic("cannot set the order of base point of secp256k1")
	}

}

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
	fn, _ := rand.Int(rand.Reader, curveN)
	return Fn{fn}
}

// Copy returns copy of the field element
func (fn *Fn) Copy() Fn {
	return Fn{new(big.Int).Set(fn.Int)}
}

// IsZero returns true if the field element is zero and false otherwise.
func (fn *Fn) IsZero() bool {
	return fn.Cmp(big.NewInt(0)) == 0
}

// Add computes the addition of the two field elements and stores the result in
// the receiver.
func (fn *Fn) Add(a *Fn, b *Fn) {
	fn.Mod(fn.Int.Add(a.Int, b.Int), curveN)
}

// Mul computes the multiplication of the two field elements and stores the
// result in the receiver.
func (fn *Fn) Mul(a *Fn, b *Fn) {
	fn.Mod(fn.Int.Mul(a.Int, b.Int), curveN)
}

// Eq returns true if the two field elements are equal, and false otherwise.
func (fn *Fn) Eq(other *Fn) bool {
	return fn.Int.Cmp(other.Int) == 0
}

// Negate computes the additive inverse of the given field element and stores
// the result in the receiver.
func (fn *Fn) Negate(a *Fn) {
	fn.Sub(curveN, a.Int)
}

// Inverse computes the multiplicative inverse of the given field element and
// stores the result in the receiver.
func (fn *Fn) Inverse(a *Fn) {
	fn.ModInverse(a.Int, curveN)
}

// Bytes returns the absolute value of fn as a big-endian byte slice.
func (fn Fn) Bytes() []byte {
	b := fn.Int.Bytes()
	if len(b) < 32 {
		b = bytes.Join([][]byte{make([]byte, 32-len(b)), b}, nil)
	}
	return b
}

// HexFnSize is the size of hex representation of Fn
const HexFnSize = 64

// Hex returns the hex-string representation of fn.
func (fn Fn) Hex() string {
	return hex.EncodeToString(fn.Bytes())
}

// SetHex sets fn to the value of s
func (fn *Fn) SetHex(s string) (err error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return
	}
	fn.Int = new(big.Int).SetBytes(b)
	return
}
