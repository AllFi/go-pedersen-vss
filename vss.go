package vss

import (
	"fmt"

	"github.com/AllFi/go-pedersen-vss/types"
)

// VShareSecret creates verifiable Shamir shares for the given secret at the
// given threshold, and returns the shares and the commitment. In the returned Shares, there will be one share for each index
// in the indices that were used to construct the Sharer.
//
// Panics: This function will panic if the destination shares slice has a
// capacity less than n (the number of indices), or if the destination
// commitment has a capacity less than k.
func VShareSecret(
	indices []types.Fn,
	h types.Point,
	secret types.Fn,
	k int,
) (
	vshares types.VerifiableShares,
	c types.Commitment,
	err error,
) {
	n := len(indices)
	vshares = make(types.VerifiableShares, n)
	c = make(types.Commitment, 0, n)

	shares := make(types.Shares, n)
	coeffs := make([]types.Fn, k)

	err = shareAndGetCoeffs(&shares, coeffs, indices, secret, k)
	if err != nil {
		return
	}

	// At this point, the sharer should still have the randomly picked
	// coefficients in its cache, which we need to use for the commitment.
	c = c[:k]
	for i, coeff := range coeffs {
		c[i] = types.NewPoint()
		c[i].BaseExp(&coeff)
	}

	setRandomCoeffs(coeffs, types.RandomFn(), k)
	for i, ind := range indices {
		vshares[i].Share = shares[i]
		polyEval(&vshares[i].Decommitment, &ind, coeffs)
	}

	// Finish the computation of the commitments
	hPow := types.NewPoint()
	for i, coeff := range coeffs {
		hPow.Scale(&h, &coeff)
		c[i].Add(&c[i], &hPow)
	}

	return
}

// IsValid returns true when the given verifiable share is valid with regard to
// the given commitment, and false otherwise.
func IsValid(h types.Point, c *types.Commitment, vshare *types.VerifiableShare) bool {
	var gPow, hPow, eval = types.NewPoint(), types.NewPoint(), types.NewPoint()
	gPow.BaseExp(&vshare.Share.Value)
	hPow.Scale(&h, &vshare.Decommitment)
	gPow.Add(&gPow, &hPow)

	evaluate(&eval, c, &vshare.Share.Index)
	return gPow.Eq(&eval)
}

// Open computes the secret corresponding to the given shares. This is
// equivalent to interpolating the polynomial that passes through the given
// points, and returning the constant term. It is assumed that all shares have
// different indices. Further properties that need to be hold if this function
// is to correctly reconstruct the secret for a sharing with threshoold k are:
//	- There are at least k shares.
//	- All shares are valid, in the sense that they have not been maliciously
//		modified.
func Open(shares types.VerifiableShares) types.Fn {
	num, denom, res, tmp := types.NewFn(), types.NewFn(), types.NewFn(), types.NewFn()
	res.SetInt64(0)
	for i := range shares {
		num.SetInt64(1)
		denom.SetInt64(1)
		for j := range shares {
			if shares[i].Share.Index.Eq(&shares[j].Share.Index) {
				continue
			}
			tmp.Negate(&shares[i].Share.Index)
			tmp.Add(&tmp, &shares[j].Share.Index)
			denom.Mul(&denom, &tmp)
			num.Mul(&num, &shares[j].Share.Index)
		}
		denom.Inverse(&denom)
		tmp.Mul(&num, &denom)
		tmp.Mul(&tmp, &shares[i].Share.Value)
		res.Add(&res, &tmp)
	}
	return res
}

// Evaluates the sharing polynomial at the given index "in the exponent".
func evaluate(eval *types.Point, c *types.Commitment, index *types.Fn) {
	*eval = (*c)[len(*c)-1].Copy()
	for i := len(*c) - 2; i >= 0; i-- {
		eval.Scale(eval, index)
		eval.Add(eval, &(*c)[i])
	}
}

// shareAndGetCoeffs is the same as ShareSecret, but uses the provided slice to
// store the generated coefficients of the sharing polynomial. If this function
// successfully returns, this slice will contain the coefficients of the
// sharing polynomial, where index 0 is the constant term.
//
// Panics: This function will panic if the destination shares slice has a
// capacity less than n (the number of indices) or the coefficients slice has
// length less than k, or any of the given indices is the zero element.
func shareAndGetCoeffs(dst *types.Shares, coeffs, indices []types.Fn, secret types.Fn, k int) error {
	for _, index := range indices {
		if index.IsZero() {
			panic("cannot create share for index zero")
		}
	}
	if k > len(indices) {
		return fmt.Errorf(
			"reconstruction threshold too large: expected k <= %v, got k = %v",
			len(indices), k,
		)
	}
	setRandomCoeffs(coeffs, secret, k)

	// Set shares
	// NOTE: This panics if the destination slice does not have the required
	// capacity.
	*dst = (*dst)[:len(indices)]
	for i, ind := range indices {
		eval := types.NewFn()
		polyEval(&eval, &ind, coeffs)
		(*dst)[i].Index = ind
		(*dst)[i].Value = eval
	}

	return nil
}

// Sets the coefficients of the Sharer to represent a random degree k-1
// polynomial with constant term equal to the given secret.
//
// Panics: This function will panic if k is greater than len(coeffs).
func setRandomCoeffs(coeffs []types.Fn, secret types.Fn, k int) {
	coeffs = coeffs[:k]
	coeffs[0] = secret

	// NOTE: If k > len(coeffs), then this will panic when i > len(coeffs).
	for i := 1; i < k; i++ {
		coeffs[i] = types.RandomFn()
	}
}

// Evaluates the polynomial defined by the given coefficients at the point x
// and stores the result in y. Modifies y, but leaves x and coeffs unchanged.
// Normalizes y, so this this is not neccesary to do manually after calling
// this function.
//
// Panics: This function assumes that len(coeffs) is at least 1 and not nil. If
// it is not, it will panic. It does not make sense to call this function if
// coeffs is the empty (or nil) slice.
func polyEval(y, x *types.Fn, coeffs []types.Fn) {
	// NOTE: This will panic if len(coeffs) is less than 1 or if coeffs is nil.
	*y = coeffs[len(coeffs)-1].Copy()
	for i := len(coeffs) - 2; i >= 0; i-- {
		y.Mul(y, x)
		y.Add(y, &coeffs[i])
	}
}
