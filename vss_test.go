package vss

import (
	"math/rand"
	"testing"

	"github.com/AllFi/go-pedersen-vss/types"
	"github.com/stretchr/testify/assert"
)

func TestBase(t *testing.T) {
	h := types.RandomPoint()
	trials := 20
	n := 20

	var k int
	var secret types.Fn

	indices := randomIndices(n)

	for i := 0; i < trials; i++ {
		// Create a random sharing.
		k = randRange(1, n-1)
		secret = types.RandomFn()
		vshares, c, err := VShareSecret(indices, h, secret, k)
		assert.NoError(t, err)

		// Check that all shares are valid.
		for _, share := range vshares {
			assert.True(t, IsValid(h, &c, &share))
		}

		shuffle(vshares)
		openedSecret := Open(vshares[:k])
		assert.Equal(t, secret, openedSecret)
	}
}

func BenchmarkVSShare(b *testing.B) {
	n := 100
	k := 33
	h := types.RandomPoint()

	indices := randomIndices(n)
	secret := types.RandomFn()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = VShareSecret(indices, h, secret, k)
	}
}

func BenchmarkVSSVerify(b *testing.B) {
	n := 100
	k := 33
	h := types.RandomPoint()

	indices := randomIndices(n)
	secret := types.RandomFn()
	vshares, c, _ := VShareSecret(indices, h, secret, k)
	ind := rand.Intn(n)
	share := vshares[ind]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsValid(h, &c, &share)
	}
}

func randomIndices(n int) []types.Fn {
	indices := make([]types.Fn, n)
	for i := range indices {
		indices[i] = types.RandomFn()
	}
	return indices
}

func randRange(lower, upper int) int {
	return rand.Intn(upper+1-lower) + lower
}

func shuffle(shares []types.VerifiableShare) {
	rand.Shuffle(len(shares), func(i, j int) {
		shares[i], shares[j] = shares[j], shares[i]
	})
}
