package issuer

import (
	"encoding/json"
	"gitlab.com/distributed_lab/logan/v3/errors"
	"time"
)

var (
	ErrUnexpectedStatusCode = errors.New("unexpected status code")
)

type UUIDResponse struct {
	Id string `json:"id"`
}

type CredentialRequest struct {
	CredentialSchema  string            `json:"credentialSchema"`
	Type              string            `json:"type"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
	Expiration        *time.Time        `json:"expiration,omitempty"`
	MtProof           bool              `json:"mtProof"`
	SignatureProof    bool              `json:"signatureProof"`
}

type CredentialSubject struct {
	ID                string `json:"id"`
	IsAdult           bool   `json:"isAdult"`
	IssuingAuthority  int64  `json:"issuingAuthority"`
	DocumentNullifier string `json:"documentNullifier"`
	CredentialHash    string `json:"credentialHash"`
}

type GetCredentialResponse struct {
	Id                    string          `json:"id"`
	ProofTypes            []string        `json:"proofTypes"`
	CreatedAt             time.Time       `json:"createdAt"`
	ExpiresAt             time.Time       `json:"expiresAt"`
	Expired               bool            `json:"expired"`
	SchemaHash            string          `json:"schemaHash"`
	SchemaType            string          `json:"schemaType"`
	SchemaUrl             string          `json:"schemaUrl"`
	Revoked               bool            `json:"revoked"`
	RevNonce              int64           `json:"revNonce"`
	CredentialSubject     json.RawMessage `json:"credentialSubject"`
	UserID                string          `json:"userID"`
	SchemaTypeDescription string          `json:"schemaTypeDescription"`
}
