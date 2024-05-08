package data

import (
	"time"

	"github.com/google/uuid"
)

type ClaimQ interface {
	New() ClaimQ
	Insert(value Claim) error
	Update(value Claim) error
	FilterBy(column string, value any) ClaimQ
	Get() (*Claim, error)
	Select() ([]Claim, error)
	Count() (int, error)
	DeleteByID(id uuid.UUID) error
	ForUpdate() ClaimQ
	ResetFilter() ClaimQ
}

type Claim struct {
	ID           uuid.UUID `db:"id" structs:"id"`
	UserDID      string    `db:"user_did" structs:"user_did"`
	IssuerDID    string    `db:"issuer_did" structs:"issuer_did"`
	Nullifier    string    `db:"nullifier" structs:"nullifier"`
	Salt         string    `db:"salt" structs:"salt"`
	DocumentHash string    `db:"document_hash" structs:"document_hash"`
	CreatedAt    time.Time `db:"created_at" structs:"-"`
	IsBanned     bool      `db:"is_banned" structs:"is_banned"`
}
