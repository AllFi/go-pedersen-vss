package types

// Share represents a single share in a Shamir secret sharing scheme.
type Share struct {
	Index, Value Fn
}

// Shares represents a slice of Shamir shares
type Shares []Share

// A VerifiableShare is a Share but with additional information that allows it
// to be verified as correct for a given commitment to a sharing.
type VerifiableShare struct {
	Share        Share
	Decommitment Fn
}

// VerifiableShares is a alias for a slice of VerifiableShare(s).
type VerifiableShares []VerifiableShare

// A Commitment is used to verify that a sharing has been performed correctly.
type Commitment []Point
