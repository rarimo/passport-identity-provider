package issuer

import (
	"github.com/google/uuid"
	"math/big"
	"strconv"
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
	did    string
}

func New(log *logan.Entry, config *config.IssuerConfig, login, password string) *Issuer {
	return &Issuer{
		client: req.C().
			SetBaseURL(config.BaseUrl).
			SetCommonBasicAuth(login, password).
			SetLogger(log),
		cfg: config,
		did: config.DID.String(),
	}
}

func (is *Issuer) DID() string {
	return is.did
}

func (is *Issuer) IssueVotingClaim(
	id string, issuingAuthority int64, isAdult bool, expiration *time.Time, nullifier *big.Int,
) (string, error) {
	var result UUIDResponse

	credHashInput := make([]*big.Int, 0)
	credHashInput = append(credHashInput, big.NewInt(1))
	credHashInput = append(credHashInput, big.NewInt(issuingAuthority))
	credHashInput = append(credHashInput, nullifier)

	credentialHash, err := poseidon.Hash(credHashInput)
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
			DocumentNullifier: nullifier.String(),
			CredentialHash:    credentialHash.String(),
		},
		//Expiration:     expiration,
		MtProof:        true,
		SignatureProof: true,
	}

	response, err := is.client.R().
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

func (is *Issuer) GetCredential(claimID uuid.UUID) (GetCredentialResponse, error) {
	var cred GetCredentialResponse

	response, err := is.client.R().
		SetSuccessResult(&cred).
		SetPathParam("id", claimID.String()).
		Get("/credentials/{id}")
	if err != nil {
		return GetCredentialResponse{}, errors.Wrap(err, "failed to send post request")
	}

	if response.StatusCode >= 299 {
		return GetCredentialResponse{}, errors.Wrap(ErrUnexpectedStatusCode, response.String())
	}

	return cred, nil
}

func (is *Issuer) RevokeClaim(revocationNonce int64) error {
	response, err := is.client.R().
		SetPathParam("nonce", strconv.FormatInt(revocationNonce, 10)).
		Post("/credentials/revoke/{nonce}")
	if err != nil {
		return errors.Wrap(err, "failed to send post request")
	}

	if response.StatusCode >= 299 {
		return errors.Wrap(ErrUnexpectedStatusCode, response.String())
	}

	return nil
}
