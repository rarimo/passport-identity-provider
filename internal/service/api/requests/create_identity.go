package requests

import (
	"encoding/json"
	"net/http"

	"github.com/iden3/go-iden3-core/v2/w3c"
	snarkTypes "github.com/iden3/go-rapidsnark/types"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type CreateIdentityRequestData struct {
	ID          *w3c.DID           `json:"id"`
	ZKProof     snarkTypes.ZKProof `json:"zkproof"`
	DocumentSOD struct {
		SignedAttributes    string `json:"signed_attributes"`
		Algorithm           string `json:"algorithm"`
		Signature           string `json:"signature"`
		PemFile             string `json:"pem_file"`
		EncapsulatedContent string `json:"encapsulated_content"`
	} `json:"document_sod"`
}

type CreateIdentityRequest struct {
	Data CreateIdentityRequestData `json:"data"`
}

func NewCreateIdentityRequest(r *http.Request) (CreateIdentityRequest, error) {
	var request CreateIdentityRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		return request, errors.Wrap(err, "failed to unmarshal")
	}

	if request.Data.DocumentSOD.EncapsulatedContent[0:2] != "30" {
		request.Data.DocumentSOD.EncapsulatedContent = "30" + request.Data.DocumentSOD.EncapsulatedContent
	}

	return request, nil
}
