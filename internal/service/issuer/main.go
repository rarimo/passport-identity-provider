package issuer

import (
	"github.com/RarimoVoting/identity-provider-service/internal/config"
	"github.com/imroc/req/v3"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
	"time"
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
	id, issuingAuthority string, isAdult bool, expiration *time.Time,
) (string, error) {
	var result UUIDResponse

	credentialRequest := CredentialRequest{
		CredentialSchema: is.cfg.CredentialSchema,
		Type:             is.cfg.ClaimType,
		CredentialSubject: CredentialSubject{
			ID:               id,
			IssuingAuthority: issuingAuthority,
			IsAdult:          isAdult,
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
