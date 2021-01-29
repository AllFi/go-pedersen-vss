package types

// Share represents a single share in a Shamir secret sharing scheme.
type Share struct {
	Index, Value Fn
}

// A VerifiableShare is a Share but with additional information that allows it
// to be verified as correct for a given commitment to a sharing.
type VerifiableShare struct {
	Share        Share
	Decommitment Fn
}

// Hex returns the hex-string representation of vs.
func (vs VerifiableShare) Hex() string {
	return vs.Share.Index.Hex() + vs.Share.Value.Hex() + vs.Decommitment.Hex()
}

// SetHex sets vs to the value of s
func (vs *VerifiableShare) SetHex(s string) (err error) {
	err = vs.Share.Index.SetHex(s[:HexFnSize])
	if err != nil {
		return
	}

	err = vs.Share.Value.SetHex(s[HexFnSize : HexFnSize*2])
	if err != nil {
		return
	}

	err = vs.Decommitment.SetHex(s[HexFnSize*2 : HexFnSize*3])
	if err != nil {
		return
	}
	return
}

// A Commitment is used to verify that a sharing has been performed correctly.
type Commitment []Point

// Hex returns the hex-string representation of c.
func (c Commitment) Hex() (s string) {
	for _, p := range c {
		s += p.Hex()
	}
	return s
}

// SetHex sets c to the value of s
func (c *Commitment) SetHex(s string) (err error) {
	*c = make(Commitment, 0)
	for i := 0; i < len(s)/HexPointSize; i++ {
		p := NewPoint()
		err = p.SetHex(s[i*HexPointSize : (i+1)*HexPointSize])
		if err != nil {
			return
		}
		*c = append(*c, p)
	}
	return
}
