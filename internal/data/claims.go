package data

import "github.com/google/uuid"

type ClaimQ interface {
	New() ClaimQ
	Insert(value Claim) error
	FilterBy(column string, value any) ClaimQ
	Get() (*Claim, error)
	Select() ([]Claim, error)
	DeleteByID(id uuid.UUID) error
	ForUpdate() ClaimQ
	ResetFilter() ClaimQ
}

type Claim struct {
	ID        uuid.UUID `db:"id" structs:"id"`
	UserDID   string    `db:"user_did" structs:"user_did"`
	IssuerDID string    `db:"issuer_did" structs:"issuer_did"`
	Document  string    `db:"document" structs:"document"`
	Revoked   bool      `db:"revoked" structs:"revoked"`
}
