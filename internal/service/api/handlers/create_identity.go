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
	"encoding/pem"
	"fmt"
	"math/big"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/verifier"
	"github.com/rarimo/certificate-transparency-go/x509"
	"github.com/rarimo/passport-identity-provider/internal/config"
	"github.com/rarimo/passport-identity-provider/internal/data"
	"github.com/rarimo/passport-identity-provider/internal/service/api/requests"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

// Full list of the OpenSSL signature algorithms and hash-functions is provided here:
// https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set1_sigalgs_list.html

const (
	SHA1   = "sha1"
	SHA256 = "sha256"

	SHA256withRSA   = "SHA256withRSA"
	SHA1withECDSA   = "SHA1withECDSA"
	SHA256withECDSA = "SHA256withECDSA"
)

var algorithmsListMap = map[string]map[string]string{
	"SHA1": {
		"ECDSA": SHA1withECDSA,
	},
	"SHA256": {
		"RSA":   SHA256withRSA,
		"ECDSA": SHA256withECDSA,
	},
}

func CreateIdentity(w http.ResponseWriter, r *http.Request) {
	req, err := requests.NewCreateIdentityRequest(r)
	if err != nil {
		Log(r).WithError(err).Error("failed to create new create identity request")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	algorithm := signatureAlgorithm(req.Data.DocumentSOD.Algorithm)
	if algorithm == "" {
		Log(r).WithError(fmt.Errorf("%s is not a valid algorithm", req.Data.DocumentSOD.Algorithm)).Error("failed to select signature algorithm")
		ape.RenderErr(w, problems.BadRequest(fmt.Errorf("%s is not a valid algorithm", req.Data.DocumentSOD.Algorithm))...)
		return
	}

	signedAttributes, err := hex.DecodeString(req.Data.DocumentSOD.SignedAttributes)
	if err != nil {
		Log(r).WithError(err).Error("failed to decode hex string")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	encapsulatedContent, err := hex.DecodeString(req.Data.DocumentSOD.EncapsulatedContent)
	if err != nil {
		Log(r).WithError(err).Error("failed to decode hex string")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	if err := validateSignedAttributes(signedAttributes, encapsulatedContent, algorithm); err != nil {
		Log(r).WithError(err).Error("failed to validate signed attributes")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	cert, err := parseCertificate([]byte(req.Data.DocumentSOD.PemFile))
	if err != nil {
		Log(r).WithError(err).Error("failed to parse certificate")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	if err := verifySignature(req, cert, signedAttributes, algorithm); err != nil {
		Log(r).WithError(err).Error("failed to verify signature")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	cfg := VerifierConfig(r)

	switch algorithm {
	case SHA1withECDSA:
		if err := verifier.VerifyGroth16(req.Data.ZKProof, cfg.VerificationKeys[SHA1]); err != nil {
			Log(r).WithError(err).Error("failed to verify Groth16")
			ape.RenderErr(w, problems.BadRequest(err)...)
			return
		}
	case SHA256withRSA, SHA256withECDSA:
		if err := verifier.VerifyGroth16(req.Data.ZKProof, cfg.VerificationKeys[SHA256]); err != nil {
			Log(r).WithError(err).Error("failed to verify Groth16")
			ape.RenderErr(w, problems.BadRequest(err)...)
			return
		}
	default:
		Log(r).WithField("algorithm", req.Data.DocumentSOD.Algorithm).Debug("invalid signature algorithm")
		ape.RenderErr(w, problems.BadRequest(errors.New("invalid signature algorithm"))...)
		return
	}

	encapsulatedData := resources.EncapsulatedData{}
	if _, err = asn1.Unmarshal(encapsulatedContent, &encapsulatedData); err != nil {
		Log(r).WithError(err).Error("failed to unmarshal ASN.1")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	privateKey := make([]asn1.RawValue, 0)
	if _, err = asn1.Unmarshal(encapsulatedData.PrivateKey.FullBytes, &privateKey); err != nil {
		Log(r).WithError(err).Error("failed to unmarshal ASN.1")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	privKeyEl := resources.PrivateKeyElement{}
	if _, err = asn1.Unmarshal(privateKey[0].FullBytes, &privKeyEl); err != nil {
		Log(r).WithError(err).Error("failed to unmarshal ASN.1")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	if err := validatePubSignals(cfg, req.Data, privKeyEl.OctetStr.Bytes); err != nil {
		Log(r).WithError(err).Error("failed to validate pub signals")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	if err := validateCert(cert, cfg.MasterCerts); err != nil {
		Log(r).WithError(err).Error("failed to validate certificate")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	masterQ := MasterQ(r)

	claim, err := masterQ.Claim().ResetFilter().
		FilterBy("user_did", req.Data.ID.String()).
		Get()
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

	identityExpiration, err := getExpirationTimeFromPubSignals(req.Data.ZKProof.PubSignals)
	if err != nil {
		Log(r).WithError(err).Error("failed to get expiration time")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	issuingAuthority, err := strconv.Atoi(req.Data.ZKProof.PubSignals[2])
	if err != nil {
		Log(r).WithError(err).Error("failed to convert string to int")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	var claimID string
	iss := Issuer(r)
	vaultClient := VaultClient(r)

	blinder, err := vaultClient.Blinder()
	if err != nil {
		Log(r).WithError(err).Error("failed to get blinder from the vault")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	// timestamp is only 6 bytes long, if using some other salt, make sure that it is
	// < 32 to be compatible with Poseidon hash function
	salt := new(big.Int).SetUint64(uint64(time.Now().UTC().UnixMilli()))
	documentHash, err := poseidon.HashBytes(signedAttributes)
	if err != nil {
		Log(r).WithError(err).Error("failed to hash signed attributes")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	nullifier, err := poseidon.Hash([]*big.Int{documentHash, blinder, salt})
	if err != nil {
		Log(r).WithError(err).Error("failed to build nullifier")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	existing, err := masterQ.Claim().FilterBy("document_hash", documentHash.String()).Get()
	if err != nil {
		Log(r).WithError(err).Error("failed to get claim by document hash")
		ape.RenderErr(w, problems.InternalError())
		return
	}
	if existing != nil {
		log := Log(r).WithField("document_hash", documentHash.String())
		if existing.IsBanned {
			log.Info("user of the provided document is banned")
			ape.RenderErr(w, problems.InternalError())
			return
		}

		count, err := masterQ.Claim().FilterBy("document_hash", documentHash.String()).Count()
		if err != nil {
			log.WithError(err).Error("failed to count claims by document hash")
			ape.RenderErr(w, problems.InternalError())
			return
		}

		if count > 0 {
			allowed := rand.Intn(cfg.MultiAccMaxLimit-cfg.MultiAccMinLimit+1) + cfg.MultiAccMinLimit
			if count >= allowed {
				err = masterQ.Claim().FilterBy("document_hash", documentHash.String()).Update(map[string]any{
					"is_banned": true,
				})

				if err != nil {
					log.WithError(err).Error("failed to ban user")
				} else {
					log.Infof("user of the provided document was banned for registering %d accounts, allowed is %d", count, allowed)
				}

				ape.RenderErr(w, problems.InternalError())
				return
			}
		}
	}

	if err := masterQ.Transaction(func(db data.MasterQ) error {
		claimID, err = iss.IssueVotingClaim(
			req.Data.ID.String(), int64(issuingAuthority), true, identityExpiration, nullifier,
		)
		if err != nil {
			ape.RenderErr(w, problems.InternalError())
			return errors.Wrap(err, "failed to issue voting claim")
		}

		if err = writeDataToDB(db, claimID, data.Claim{
			UserDID:      req.Data.ID.String(),
			IssuerDID:    iss.DID(),
			Nullifier:    nullifier.String(),
			Salt:         salt.String(),
			DocumentHash: documentHash.String(),
		}); err != nil {
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

func parseCertificate(pemFile []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemFile)
	if block == nil {
		return nil, fmt.Errorf("invalid certificate: invalid PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse certificate")
	}

	return cert, nil
}

func validateSignedAttributes(signedAttributes, encapsulatedContent []byte, algorithm string) error {
	signedAttributesASN1 := make([]asn1.RawValue, 0)

	if _, err := asn1.UnmarshalWithParams(signedAttributes, &signedAttributesASN1, "set"); err != nil {
		return errors.Wrap(err, "failed to unmarshal ASN1 with params")
	}

	if len(signedAttributesASN1) == 0 {
		return errors.New("signed attributes amount is 0")
	}

	digestAttr := resources.DigestAttribute{}
	if _, err := asn1.Unmarshal(signedAttributesASN1[len(signedAttributesASN1)-1].FullBytes, &digestAttr); err != nil {
		return errors.Wrap(err, "failed to unmarshal ASN1")
	}

	d := make([]byte, 0)
	switch algorithm {
	case SHA1withECDSA:
		h := sha1.New()
		h.Write(encapsulatedContent)
		d = h.Sum(nil)
	case SHA256withRSA, SHA256withECDSA:
		h := sha256.New()
		h.Write(encapsulatedContent)
		d = h.Sum(nil)
	default:
		return errors.New(fmt.Sprintf("%s is not supported algorithm", algorithm))
	}

	if len(digestAttr.Digest) == 0 {
		return errors.New("signed attributes digest values amount is 0")
	}

	if !bytes.Equal(digestAttr.Digest[0].Bytes, d) {
		return errors.From(errors.New("digest signed attribute is not equal to encapsulated content hash"), logan.F{
			"signed_attributes": hex.EncodeToString(digestAttr.Digest[0].Bytes),
			"content_hash":      hex.EncodeToString(d),
		})
	}
	return nil
}

func signatureAlgorithm(passedAlgorithm string) string {
	if passedAlgorithm == "rsaEncryption" {
		return SHA256withRSA
	}

	if strings.Contains(strings.ToUpper(passedAlgorithm), "PSS") {
		return "" // RSA-PSS is not currently supported
	}

	for hashFunc, signatureAlgorithms := range algorithmsListMap {
		if strings.Contains(strings.ToUpper(passedAlgorithm), hashFunc) {
			for signatureAlgo, algorithmName := range signatureAlgorithms {
				if strings.Contains(strings.ToUpper(passedAlgorithm), signatureAlgo) {
					return algorithmName
				}
			}
		}
	}
	return ""
}

func writeDataToDB(
	db data.MasterQ,
	claimIDStr string,
	claim data.Claim,
) error {
	var err error
	claim.ID, err = uuid.Parse(claimIDStr)
	if err != nil {
		return errors.Wrap(err, "failed to parse uuid")
	}

	if err = db.Claim().Insert(claim); err != nil {
		return errors.Wrap(err, "failed to insert claim in the database")
	}

	return nil
}

func verifySignature(req requests.CreateIdentityRequest, cert *x509.Certificate, signedAttributes []byte, algo string) error {
	signature, err := hex.DecodeString(req.Data.DocumentSOD.Signature)
	if err != nil {
		return errors.Wrap(err, "failed to decode hex string")
	}

	switch algo {
	case SHA256withRSA:
		pubKey := cert.PublicKey.(*rsa.PublicKey)

		h := sha256.New()
		h.Write(signedAttributes)
		d := h.Sum(nil)

		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, d, signature); err != nil {
			return errors.Wrap(err, "failed to verify SHA256 with RSA signature")
		}
	case SHA1withECDSA:
		pubKey := cert.PublicKey.(*ecdsa.PublicKey)

		h := sha1.New()
		h.Write(signedAttributes)
		d := h.Sum(nil)

		if !ecdsa.VerifyASN1(pubKey, d, signature) {
			return errors.New("failed to verify SHA1 with ECDSA signature")
		}
	case SHA256withECDSA:
		pubKey := cert.PublicKey.(*ecdsa.PublicKey)

		h := sha256.New()
		h.Write(signedAttributes)
		d := h.Sum(nil)

		if !ecdsa.VerifyASN1(pubKey, d, signature) {
			return errors.New("failed to verify SHA256 with ECDSA signature")
		}
	default:
		return errors.New(fmt.Sprintf("%s is unsupported algorithm", req.Data.DocumentSOD.Algorithm))
	}

	return nil
}

func validateCert(cert *x509.Certificate, masterCertsPem []byte) error {
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

	currentTime := time.Now().UTC()

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
