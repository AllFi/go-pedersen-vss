package types

import (
	"math/big"

	"github.com/ing-bank/zkrp/crypto/p256"
)

// Point represents a point (group element) on the secp256k1 elliptic curve.
type Point struct {
	*p256.P256
}

// NewPoint returns a new point on the elliptic curve
func NewPoint() Point {
	p := Point{new(p256.P256)}
	p.X = big.NewInt(0)
	p.Y = big.NewInt(0)
	return p
}

// RandomPoint generates a random point on the elliptic curve.
func RandomPoint(seed string) Point {
	p, _ := p256.MapToGroup(seed)
	return Point{p}
}

// Copy returns a copy of the point on the elliptic curve
func (p *Point) Copy() Point {
	c := NewPoint()
	c.X.Set(p.X)
	c.Y.Set(p.Y)
	return c
}

// BaseExp computes the scalar multiplication of the canonical generator of the
// curve by the given scalar.
func (p *Point) BaseExp(scalar *Fn) {
	if scalar == nil {
		panic("expected first argument to not be nil")
	}
	p.ScalarBaseMult(scalar.Int)
}

// Scale computes the scalar multiplication of the given curve point by the
// given scalar.
//
//NOTE: It is assumed that the input point is not the point at infinity.
func (p *Point) Scale(a *Point, scalar *Fn) {
	if a == nil {
		panic("expected first argument to not be nil")
	}
	if scalar == nil {
		panic("expected second argument to not be nil")
	}

	p.ScalarMult(a.P256, scalar.Int)
}

// Add computes the curve addition of the two given curve points.
func (p *Point) Add(a, b *Point) {
	if a == nil {
		panic("expected first argument to be not be nil")
	}
	if b == nil {
		panic("expected second argument to be not be nil")
	}

	p.Multiply(a.P256, b.P256)
}

// Eq returns true if the two curve points are equal, and false otherwise.
func (p *Point) Eq(other *Point) bool {
	sub := NewPoint()
	sub.Multiply(p.P256, other.ScalarMult(other.P256, big.NewInt(-1)))
	return sub.IsZero()
}
