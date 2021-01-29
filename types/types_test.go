package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFnSerialization(t *testing.T) {
	fn := RandomFn()
	fn2 := NewFn()
	err := fn2.SetHex(fn.Hex())
	assert.NoError(t, err)
	assert.True(t, fn.Eq(&fn2))
}

func TestPointSerialization(t *testing.T) {
	p := RandomPoint()
	p2 := NewPoint()
	err := p2.SetHex(p.Hex())
	assert.NoError(t, err)
	assert.True(t, p.Eq(&p2))
}

func TestVerifiableShareSerialization(t *testing.T) {
	vs := VerifiableShare{Share{RandomFn(), RandomFn()}, RandomFn()}
	vs2 := VerifiableShare{}
	err := vs2.SetHex(vs.Hex())
	assert.NoError(t, err)
	assert.True(t, vs.Share.Index.Eq(&vs2.Share.Index))
	assert.True(t, vs.Share.Value.Eq(&vs2.Share.Value))
	assert.True(t, vs.Decommitment.Eq(&vs2.Decommitment))
}

func TestCommitmentSerialization(t *testing.T) {
	c := Commitment{RandomPoint(), RandomPoint(), RandomPoint()}
	c2 := Commitment{}
	err := c2.SetHex(c.Hex())
	assert.NoError(t, err)
	for i := 0; i < len(c); i++ {
		assert.True(t, c[i].Eq(&c2[i]))
	}
}
