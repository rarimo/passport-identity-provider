package handlers

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
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

	if err := verifySHA256WithRSA(req); err != nil {
		Log(r).WithError(err).Error("failed to verify SHA256 with RSA")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	if err := verifier.VerifyGroth16(req.Data.ZKProof, cfg.VerificationKey); err != nil {
		Log(r).WithError(err).Debug("failed to verify Groth16")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	encapsulatedContentBytes, err := hex.DecodeString(req.Data.DocumentSOD.EncapsulatedContent)
	if err != nil {
		Log(r).WithError(err).Error("failed to decode hex string")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	encapsulatedData := resources.EncapsulatedData{}
	_, err = asn1.Unmarshal(encapsulatedContentBytes, &encapsulatedData)
	if err != nil {
		Log(r).WithError(err).Error("failed to unmarshal ASN.1")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	if err := validatePubSignals(cfg, req.Data, encapsulatedData.PrivateKey.El1.OctetStr.Bytes); err != nil {
		Log(r).WithError(err).Debug("failed to validate pub signals")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	if err := validateCert([]byte(req.Data.DocumentSOD.PemFile), cfg.MasterCerts); err != nil {
		Log(r).WithError(err).Error("failed to validate certificate")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	iss := Issuer(r)

	identityExpiration, err := getExpirationTimeFromPubSignals(req.Data.ZKProof.PubSignals)
	if err != nil {
		Log(r).WithError(err).Error("failed to get expiration time")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	id, err := iss.IssueClaim(
		req.Data.ID, cfg.IssuingAuthority, true, identityExpiration,
		encapsulatedData.PrivateKey.El2.OctetStr.Bytes,
	)
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

	DocumentSOD, err := json.Marshal(req.Data.DocumentSOD)
	if err != nil {
		return errors.Wrap(err, "failed to marshal JSON")
	}

	if err := ProofsQ(r).New().Insert(data.Proof{
		DID:         req.Data.ID,
		Data:        proofData,
		PubSignals:  pubSignals,
		DocumentSOD: DocumentSOD,
	}); err != nil {
		return errors.Wrap(err, "failed to insert proof in the database")
	}

	return nil
}

func verifySHA256WithRSA(req requests.CreateIdentityRequest) error {
	block, _ := pem.Decode([]byte(req.Data.DocumentSOD.PemFile))
	if block == nil {
		return fmt.Errorf("invalid certificate: invalid PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}

	pubKey := cert.PublicKey.(*rsa.PublicKey)

	messageBytes, err := hex.DecodeString(req.Data.DocumentSOD.SignedAttributes)
	if err != nil {
		return errors.Wrap(err, "failed to decode hex string")
	}

	h := sha256.New()
	h.Write(messageBytes)
	d := h.Sum(nil)

	signature, err := hex.DecodeString(req.Data.DocumentSOD.Signature)
	if err != nil {
		return errors.Wrap(err, "failed to decode hex string")
	}

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

func validatePubSignals(
	cfg *config.VerifierConfig, requestData requests.CreateIdentityRequestData, dg1 []byte,
) error {
	if err := validatePubSignalsDG1Hash(dg1, requestData.ZKProof.PubSignals); err != nil {
		return errors.Wrap(err, "failed to validate DG1 hash")
	}

	if err := validatePubSignalsCurrentDate(requestData.ZKProof.PubSignals); err != nil {
		return fmt.Errorf("invalid current date: %w", err)
	}

	if err := validatePubSignalsAge(cfg, requestData.ZKProof.PubSignals[9]); err != nil {
		return errors.Wrap(err, "failed to validate pub signals age")
	}

	return nil
}

func validatePubSignalsDG1Hash(dg1 []byte, pubSignals []string) error {
	ints, err := stringsToArrayBigInt([]string{pubSignals[0], pubSignals[1]})
	if err != nil {
		return errors.Wrap(err, "failed to convert strings to big integers")
	}

	hashBytes := make([]byte, 0)
	hashBytes = append(hashBytes, ints[0].Bytes()...)
	hashBytes = append(hashBytes, ints[1].Bytes()...)

	if !bytes.Equal(dg1, hashBytes) {
		return errors.New("encapsulated data and proof pub signals hashes are different")
	}

	return nil
}

func validatePubSignalsCurrentDate(pubSignals []string) error {
	year, err := strconv.Atoi(pubSignals[3])
	if err != nil {
		return fmt.Errorf("invalid year: %w", err)
	}

	month, err := strconv.Atoi(pubSignals[4])
	if err != nil {
		return fmt.Errorf("invalid month: %w", err)
	}

	day, err := strconv.Atoi(pubSignals[5])
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

func validatePubSignalsAge(cfg *config.VerifierConfig, agePubSignal string) error {
	age, err := strconv.Atoi(agePubSignal)
	if err != nil {
		return errors.Wrap(err, "failed to convert pub input to int")
	}
	if age < cfg.AllowedAge {
		return errors.New("invalid age")
	}
	return nil
}

func getExpirationTimeFromPubSignals(pubSignals []string) (*time.Time, error) {
	year, err := strconv.Atoi(pubSignals[6])
	if err != nil {
		return nil, fmt.Errorf("invalid year: %w", err)
	}

	month, err := strconv.Atoi(pubSignals[7])
	if err != nil {
		return nil, fmt.Errorf("invalid month: %w", err)
	}

	day, err := strconv.Atoi(pubSignals[8])
	if err != nil {
		return nil, fmt.Errorf("invalid day: %w", err)
	}

	expirationDate := time.Date(2000+year, time.Month(month), day, 0, 0, 0, 0, time.UTC)

	return &expirationDate, nil
}

func stringsToArrayBigInt(publicSignals []string) ([]*big.Int, error) {
	p := make([]*big.Int, 0, len(publicSignals))
	for _, s := range publicSignals {
		sb, err := stringToBigInt(s)
		if err != nil {
			return nil, err
		}
		p = append(p, sb)
	}
	return p, nil
}

func stringToBigInt(s string) (*big.Int, error) {
	base := 10
	if bytes.HasPrefix([]byte(s), []byte("0x")) {
		base = 16
		s = strings.TrimPrefix(s, "0x")
	}
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, fmt.Errorf("can not parse string to *big.Int: %s", s)
	}
	return n, nil
}
