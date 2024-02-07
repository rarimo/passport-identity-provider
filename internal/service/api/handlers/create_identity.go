package handlers

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/RarimoVoting/identity-provider-service/internal/config"
	"github.com/RarimoVoting/identity-provider-service/internal/data"
	"github.com/RarimoVoting/identity-provider-service/internal/service/api/requests"
	"github.com/RarimoVoting/identity-provider-service/resources"
	"github.com/iden3/go-rapidsnark/verifier"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

func CreateIdentity(w http.ResponseWriter, r *http.Request) {
	req, err := requests.NewCreateIdentityRequest(r)
	if err != nil {
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	cfg := VerifierConfig(r)

	if err := verifier.VerifyGroth16(req.Data.ZKProof, cfg.VerificationKey); err != nil {
		Log(r).WithError(err).Debug("failed to verify Groth16")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	if err := validatePubInputs(cfg, req.Data.ZKProof.PubSignals); err != nil {
		Log(r).WithError(err).Debug("failed to validate pub inputs")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	// TODO: Verify if the DG1 hash is the same as the one in the proof

	if err := validateCert([]byte(req.Data.IDCardSOD.PemFile), cfg.MasterCerts); err != nil {
		Log(r).WithError(err).Error("failed to validate certificate")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	iss := Issuer(r)

	identityExpiration, err := getExpirationTimeFromPubInputs(req.Data.ZKProof.PubSignals)
	if err != nil {
		Log(r).WithError(err).Error("failed to get expiration time")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	id, err := iss.IssueClaim(req.Data.ID, cfg.IssuingAuthority, true, identityExpiration)
	if err != nil {
		Log(r).WithError(err).Error("failed to issue voting claim")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	if err := writeProof(r, req); err != nil {
		Log(r).WithError(err).Error("failed to write proof to the database")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	response := resources.ClaimResponse{
		Data: resources.Claim{
			Key: resources.Key{
				ID:   id,
				Type: resources.CLAIMS,
			},
			Attributes: resources.ClaimAttributes{
				ClaimId: id,
			},
		},
	}

	ape.Render(w, response)
}

func writeProof(r *http.Request, req requests.CreateIdentityRequest) error {
	proofData, err := json.Marshal(req.Data.ZKProof.Proof)
	if err != nil {
		return errors.Wrap(err, "failed to marshal JSON")
	}

	pubSignals, err := json.Marshal(req.Data.ZKProof.PubSignals)
	if err != nil {
		return errors.Wrap(err, "failed to marshal JSON")
	}

	idCardSOD, err := json.Marshal(req.Data.IDCardSOD)
	if err != nil {
		return errors.Wrap(err, "failed to marshal JSON")
	}

	if err := ProofsQ(r).New().Insert(data.Proof{
		Data:       proofData,
		PubSignals: pubSignals,
		IDCardSOD:  idCardSOD,
	}); err != nil {
		return errors.Wrap(err, "failed to insert proof in the database")
	}

	return nil
}

// TODO
func verifySHA256WithRSA(certPem, message, signature []byte) error {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return fmt.Errorf("invalid certificate: invalid PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}

	pubKey := cert.PublicKey.(*rsa.PublicKey)

	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, d, signature); err != nil {
		return errors.Wrap(err, "failed to verify signature")
	}

	return nil
}

func validateCert(certPem []byte, masterCertsPem []byte) error {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return fmt.Errorf("invalid certificate: invalid PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(masterCertsPem)

	foundCerts, err := cert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	if err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}

	if len(foundCerts) == 0 {
		return fmt.Errorf("invalid certificate: no valid certificate found")
	}

	return nil
}

func validatePubInputs(cfg *config.VerifierConfig, pubInputs []string) error {
	if err := validatePubInputsCurrentDate(pubInputs); err != nil {
		return fmt.Errorf("invalid current date: %w", err)
	}

	age, err := strconv.Atoi(pubInputs[9])
	if err != nil {
		return errors.Wrap(err, "failed to convert pub input to int")
	}
	if age < cfg.AllowedAge {
		return errors.New("invalid age")
	}

	return nil
}

func validatePubInputsCurrentDate(pubInputs []string) error {
	year, err := strconv.Atoi(pubInputs[3])
	if err != nil {
		return fmt.Errorf("invalid year: %w", err)
	}

	month, err := strconv.Atoi(pubInputs[4])
	if err != nil {
		return fmt.Errorf("invalid month: %w", err)
	}

	day, err := strconv.Atoi(pubInputs[5])
	if err != nil {
		return fmt.Errorf("invalid day: %w", err)
	}

	currentTime := time.Now()

	if currentTime.Year() != (2000 + year) {
		return fmt.Errorf("invalid year, expected %d, got %d", currentTime.Year(), 2000+year)
	}

	if currentTime.Month() != time.Month(month) {
		return fmt.Errorf("invalid month, expected %d, got %d", currentTime.Month(), month)
	}

	if currentTime.Day() != day {
		return fmt.Errorf("invalid day, expected %d, got %d", currentTime.Day(), day)
	}

	return nil
}

func getExpirationTimeFromPubInputs(pubInputs []string) (*time.Time, error) {
	year, err := strconv.Atoi(pubInputs[6])
	if err != nil {
		return nil, fmt.Errorf("invalid year: %w", err)
	}

	month, err := strconv.Atoi(pubInputs[7])
	if err != nil {
		return nil, fmt.Errorf("invalid month: %w", err)
	}

	day, err := strconv.Atoi(pubInputs[8])
	if err != nil {
		return nil, fmt.Errorf("invalid day: %w", err)
	}

	expirationDate := time.Date(2000+year, time.Month(month), day, 0, 0, 0, 0, time.UTC)

	return &expirationDate, nil
}
