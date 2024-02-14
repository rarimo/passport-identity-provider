package data

type MasterQ interface {
	New() MasterQ

	Proof() ProofQ
	Claim() ClaimQ

	Transaction(fn func(db MasterQ) error) error
}
