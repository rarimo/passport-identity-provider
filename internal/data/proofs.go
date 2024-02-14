package data

import (
	"encoding/json"
	"github.com/google/uuid"
)

type ProofQ interface {
	New() ProofQ
	Insert(value Proof) error
}

type Proof struct {
	ID          int64           `db:"id" structs:"-"`
	DID         string          `db:"did" structs:"did"`
	ClaimID     uuid.UUID       `db:"claim_id" structs:"claim_id"`
	Data        json.RawMessage `db:"data" structs:"data"`
	PubSignals  json.RawMessage `db:"pub_signals" structs:"pub_signals"`
	DocumentSOD json.RawMessage `db:"document_sod" structs:"document_sod"`
}
