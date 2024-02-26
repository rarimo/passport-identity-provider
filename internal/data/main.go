package data

type MasterQ interface {
	New() MasterQ

	Claim() ClaimQ

	Transaction(fn func(db MasterQ) error) error
}
