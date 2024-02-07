package issuer

import (
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
	ID               string `json:"id"`
	IsAdult          bool   `json:"isAdult"`
	IssuingAuthority string `json:"issuingAuthority"`
}
