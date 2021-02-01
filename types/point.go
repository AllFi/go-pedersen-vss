package types

import (
	"bytes"
	"encoding/hex"

	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/pkg/errors"
)

var context *secp256k1.Context

func init() {
	var err error
	context, err = secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		err = errors.Wrap(err, "cannot create secp256k1.Context")
		panic(err)
	}
}

// Point represents a point (group element) on the secp256k1 elliptic curve.
type Point struct {
	*secp256k1.PublicKey
}

// NewPoint returns a new point on the elliptic curve
func NewPoint() Point {
	return Point{}
}

// RandomPoint generates a random point on the elliptic curve.
func RandomPoint() Point {
	_, pk, err := secp256k1.EcPubkeyCreate(context, RandomFn().Bytes())
	if err != nil {
		panic(err)
	}
	return Point{pk}
}

// GeneratorH returns alternate secp256k1 generator, used in Elements Alpha
func GeneratorH() Point {
	/** Alternate secp256k1 generator, used in Elements Alpha.
	*  Computed as the hash of the above G, DER-encoded with 0x04 (uncompressed pubkey) as its flag byte.
	*  import hashlib
	*  C = EllipticCurve ([F (0), F (7)])
	*  G_bytes = '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'.decode('hex')
	*  H = C.lift_x(int(hashlib.sha256(G_bytes).hexdigest(),16))
	 */
	var hBytes = [65]byte{0x04,
		0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
		0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
		0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e, 0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
		0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68, 0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04}
	_, pk, err := secp256k1.EcPubkeyParse(context, hBytes[:])
	if err != nil {
		panic(err)
	}
	return Point{pk}
}

// Copy returns a copy of the point on the elliptic curve
func (p *Point) Copy() Point {
	_, pk, err := secp256k1.EcPubkeyParse(context, p.Bytes())
	if err != nil {
		panic(err)
	}
	return Point{pk}
}

// BaseExp computes the scalar multiplication of the canonical generator of the
// curve by the given scalar.
func (p *Point) BaseExp(scalar *Fn) {
	if scalar == nil {
		panic("expected first argument to not be nil")
	}

	var err error
	_, p.PublicKey, err = secp256k1.EcPubkeyCreate(context, scalar.Bytes())
	if err != nil {
		panic(err)
	}
	return
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

	p.PublicKey = a.Copy().PublicKey
	_, err := secp256k1.EcPubkeyTweakMul(context, p.PublicKey, scalar.Bytes())
	if err != nil {
		panic(err)
	}
}

// Add computes the curve addition of the two given curve points.
func (p *Point) Add(a, b *Point) {
	if a == nil {
		panic("expected first argument to be not be nil")
	}
	if b == nil {
		panic("expected second argument to be not be nil")
	}

	publicKeys := make([]*secp256k1.PublicKey, 0)
	for _, point := range []*Point{a, b} {
		if point.PublicKey != nil {
			publicKeys = append(publicKeys, point.PublicKey)
		}
	}

	var err error
	_, p.PublicKey, err = secp256k1.EcPubkeyCombine(context, publicKeys)
	if err != nil {
		panic(err)
	}
}

// Eq returns true if the two curve points are equal, and false otherwise.
func (p *Point) Eq(other *Point) bool {
	return bytes.Equal(p.Bytes(), other.Bytes())
}

// Bytes returns the absolute value of p as a big-endian byte slice.
func (p Point) Bytes() []byte {
	_, bytes, err := secp256k1.EcPubkeySerialize(context, p.PublicKey, secp256k1.EcCompressed)
	if err != nil {
		panic(err)
	}
	return bytes
}

// HexFnSize is the size of hex representation of Point
const HexPointSize = secp256k1.LenCompressed * 2

// Hex returns the hex-string representation of p.
func (p Point) Hex() string {
	return hex.EncodeToString(p.Bytes())
}

// SetHex sets p to the value of s
func (p *Point) SetHex(s string) (err error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return
	}

	_, pk, err := secp256k1.EcPubkeyParse(context, b)
	if err != nil {
		return
	}

	p.PublicKey = pk
	return
}
