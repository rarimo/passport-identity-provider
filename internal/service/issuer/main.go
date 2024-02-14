package issuer

import (
	"math/big"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/imroc/req/v3"
	"github.com/rarimo/passport-identity-provider/internal/config"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type Issuer struct {
	log    *logan.Entry
	client *req.Client
	cfg    *config.IssuerConfig
}

func New(log *logan.Entry, config *config.IssuerConfig) *Issuer {
	return &Issuer{
		client: req.C().
			SetBaseURL(config.BaseUrl).
			SetLogger(log),
		cfg: config,
	}
}

func (is *Issuer) IssueClaim(
	id string, issuingAuthority int64, isAdult bool, expiration *time.Time, dg2 []byte,
) (string, error) {
	var result UUIDResponse

	nullifierHash, err := poseidon.HashBytes(dg2)
	if err != nil {
		return "", errors.Wrap(err, "failed to hash bytes")
	}

	credHashInput := make([]byte, 0)
	credHashInput = append(credHashInput, 1)
	credHashInput = append(credHashInput, big.NewInt(issuingAuthority).Bytes()...)
	credHashInput = append(credHashInput, nullifierHash.Bytes()...)

	credentialHash, err := poseidon.HashBytes(credHashInput)
	if err != nil {
		return "", errors.Wrap(err, "failed to hash bytes")
	}

	credentialRequest := CredentialRequest{
		CredentialSchema: is.cfg.CredentialSchema,
		Type:             is.cfg.ClaimType,
		CredentialSubject: CredentialSubject{
			ID:                id,
			IssuingAuthority:  issuingAuthority,
			IsAdult:           isAdult,
			DocumentNullifier: nullifierHash.String(),
			CredentialHash:    credentialHash.String(),
		},
		Expiration:     expiration,
		MtProof:        true,
		SignatureProof: true,
	}

	response, err := is.client.R().
		SetBasicAuth(is.cfg.AuthUsername, is.cfg.AuthPassword).
		SetBodyJsonMarshal(credentialRequest).
		SetSuccessResult(&result).
		Post("/credentials")
	if err != nil {
		return "", errors.Wrap(err, "failed to send post request")
	}

	if response.StatusCode >= 299 {
		return "", errors.Wrap(ErrUnexpectedStatusCode, response.String())
	}

	return result.Id, nil
}
