package handlers

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
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

	"github.com/google/uuid"
	"github.com/iden3/go-rapidsnark/verifier"
	"github.com/rarimo/certificate-transparency-go/x509"
	"github.com/rarimo/passport-identity-provider/internal/config"
	"github.com/rarimo/passport-identity-provider/internal/data"
	"github.com/rarimo/passport-identity-provider/internal/service/api/requests"
	"github.com/rarimo/passport-identity-provider/internal/service/issuer"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

// Full list of the OpenSSL signature algorithms and hash-functions is provided here:
// https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set1_sigalgs_list.html

const (
	SHA256withRSA   = "SHA256withRSA"
	SHA1withECDSA   = "SHA1withECDSA"
	SHA256withECDSA = "SHA256withECDSA"
)

var algorithms = map[string]string{
	"SHA256withRSA": SHA256withRSA,

	"SHA1withECDSA":   SHA1withECDSA,
	"ecdsa-with-SHA1": SHA1withECDSA,

	"SHA256withECDSA": SHA256withECDSA,
}

func CreateIdentity(w http.ResponseWriter, r *http.Request) {
	req, err := requests.NewCreateIdentityRequest(r)
	if err != nil {
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	var claimID string
	iss := Issuer(r)
	masterQ := MasterQ(r)

	claim, err := masterQ.Claim().ResetFilter().FilterBy("user_did", req.Data.ID).Get()
	if err != nil {
		Log(r).WithError(err).Error("failed to get claim by user DID")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	if claim != nil {
		response := resources.ClaimResponse{
			Data: resources.Claim{
				Key: resources.Key{
					ID:   claim.ID.String(),
					Type: resources.CLAIMS,
				},
				Attributes: resources.ClaimAttributes{
					ClaimId:   claim.ID.String(),
					IssuerDid: claim.IssuerDID,
				},
			},
		}
		ape.Render(w, response)
		return
	}

	if err := masterQ.Transaction(func(db data.MasterQ) error {
		cfg := VerifierConfig(r)

		if err := verifySignature(req); err != nil {
			ape.RenderErr(w, problems.InternalError())
			return errors.Wrap(err, "failed to verify signature")
		}

		if err := verifier.VerifyGroth16(req.Data.ZKProof, cfg.VerificationKey); err != nil {
			ape.RenderErr(w, problems.BadRequest(err)...)
			return errors.Wrap(err, "failed to verify Groth16")
		}

		encapsulatedContentBytes, err := hex.DecodeString(req.Data.DocumentSOD.EncapsulatedContent)
		if err != nil {
			ape.RenderErr(w, problems.InternalError())
			return errors.Wrap(err, "failed to decode hex string")
		}

		encapsulatedData := resources.EncapsulatedData{}
		_, err = asn1.Unmarshal(encapsulatedContentBytes, &encapsulatedData)
		if err != nil {
			ape.RenderErr(w, problems.InternalError())
			return errors.Wrap(err, "failed to unmarshal ASN.1")
		}

		if err := validatePubSignals(cfg, req.Data, encapsulatedData.PrivateKey.El1.OctetStr.Bytes); err != nil {
			ape.RenderErr(w, problems.BadRequest(err)...)
			return errors.Wrap(err, "failed to validate pub signals")
		}

		if err := validateCert([]byte(req.Data.DocumentSOD.PemFile), cfg.MasterCerts); err != nil {
			ape.RenderErr(w, problems.BadRequest(err)...)
			return errors.Wrap(err, "failed to validate certificate")
		}

		identityExpiration, err := getExpirationTimeFromPubSignals(req.Data.ZKProof.PubSignals)
		if err != nil {
			ape.RenderErr(w, problems.BadRequest(err)...)
			return errors.Wrap(err, "failed to get expiration time")
		}

		issuingAuthority, err := strconv.Atoi(req.Data.ZKProof.PubSignals[2])
		if err != nil {
			ape.RenderErr(w, problems.InternalError())
			return errors.Wrap(err, "failed to convert string to int")
		}

		// check if there is a claim for this document already
		claim, err := db.Claim().ResetFilter().
			FilterBy("document", req.Data.DocumentSOD.SignedAttributes).
			ForUpdate().
			Get()
		if err != nil {
			ape.RenderErr(w, problems.InternalError())
			return errors.Wrap(err, "failed to get claim")
		}

		// revoke if so
		if claim != nil {
			if err := revokeOutdatedClaim(db, iss, claim.ID); err != nil {
				ape.RenderErr(w, problems.InternalError())
				return errors.Wrap(err, "failed to revoke outdated claim")
			}
		}

		claimID, err = iss.IssueVotingClaim(
			req.Data.ID, int64(issuingAuthority), true, identityExpiration,
			encapsulatedData.PrivateKey.El2.OctetStr.Bytes, cfg.Blinder,
		)
		if err != nil {
			ape.RenderErr(w, problems.InternalError())
			return errors.Wrap(err, "failed to issue voting claim")
		}

		if err := writeDataToDB(db, req, claimID, iss.DID()); err != nil {
			ape.RenderErr(w, problems.InternalError())
			return errors.Wrap(err, "failed to write proof to the database")
		}

		return nil
	}); err != nil {
		Log(r).WithError(err).Error("failed to execute SQL transaction")
		// error was rendered beforehand
		return
	}

	response := resources.ClaimResponse{
		Data: resources.Claim{
			Key: resources.Key{
				ID:   claimID,
				Type: resources.CLAIMS,
			},
			Attributes: resources.ClaimAttributes{
				ClaimId:   claimID,
				IssuerDid: iss.DID(),
			},
		},
	}

	ape.Render(w, response)
}

func revokeOutdatedClaim(db data.MasterQ, iss *issuer.Issuer, claimID uuid.UUID) error {
	cred, err := iss.GetCredential(claimID)
	if err != nil {
		return errors.Wrap(err, "failed to get credential")
	}

	if !cred.Revoked {
		if err := iss.RevokeClaim(cred.RevNonce); err != nil {
			return errors.Wrap(err, "failed to revoke claim")
		}
	}

	if err := db.Claim().DeleteByID(claimID); err != nil {
		return errors.Wrap(err, "failed to delete claim")
	}

	return nil
}

func writeDataToDB(db data.MasterQ, req requests.CreateIdentityRequest, claimIDStr, issuerDID string) error {
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

	claimID, err := uuid.Parse(claimIDStr)
	if err != nil {
		return errors.Wrap(err, "failed to parse uuid")
	}

	if err := db.Proof().Insert(data.Proof{
		DID:         req.Data.ID,
		ClaimID:     claimID,
		Data:        proofData,
		PubSignals:  pubSignals,
		DocumentSOD: DocumentSOD,
	}); err != nil {
		return errors.Wrap(err, "failed to insert proof in the database")
	}

	if err := db.Claim().Insert(data.Claim{
		ID:        claimID,
		UserDID:   req.Data.ID,
		IssuerDID: issuerDID,
		Document:  req.Data.DocumentSOD.SignedAttributes,
	}); err != nil {
		return errors.Wrap(err, "failed to insert claim in the database")
	}

	return nil
}

func verifySignature(req requests.CreateIdentityRequest) error {
	block, _ := pem.Decode([]byte(req.Data.DocumentSOD.PemFile))
	if block == nil {
		return fmt.Errorf("invalid certificate: invalid PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}

	messageBytes, err := hex.DecodeString(req.Data.DocumentSOD.SignedAttributes)
	if err != nil {
		return errors.Wrap(err, "failed to decode hex string")
	}

	signature, err := hex.DecodeString(req.Data.DocumentSOD.Signature)
	if err != nil {
		return errors.Wrap(err, "failed to decode hex string")
	}

	switch algorithms[req.Data.DocumentSOD.Algorithm] {
	case SHA256withRSA:
		pubKey := cert.PublicKey.(*rsa.PublicKey)

		h := sha256.New()
		h.Write(messageBytes)
		d := h.Sum(nil)

		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, d, signature); err != nil {
			return errors.Wrap(err, "failed to verify SHA256 with RSA signature")
		}
	case SHA1withECDSA:
		pubKey := cert.PublicKey.(*ecdsa.PublicKey)

		h := sha1.New()
		h.Write(messageBytes)
		d := h.Sum(nil)

		if !ecdsa.VerifyASN1(pubKey, d, signature) {
			return errors.New("failed to verify SHA1 with ECDSA signature")
		}
	case SHA256withECDSA:
		pubKey := cert.PublicKey.(*ecdsa.PublicKey)

		h := sha256.New()
		h.Write(messageBytes)
		d := h.Sum(nil)

		if !ecdsa.VerifyASN1(pubKey, d, signature) {
			return errors.New("failed to verify SHA256 with ECDSA signature")
		}
	default:
		return errors.New(fmt.Sprintf("%s is unsupported algorithm", req.Data.DocumentSOD.Algorithm))
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
