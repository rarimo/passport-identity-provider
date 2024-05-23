package requests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/iden3/go-iden3-core/v2/w3c"
	snarkTypes "github.com/iden3/go-rapidsnark/types"
	"github.com/rarimo/passport-identity-provider/internal/service/api"
	"gitlab.com/distributed_lab/logan/v3"
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

	encapsulatedContent := PrependPrefix(request.Data.DocumentSOD.EncapsulatedContent)
	if strings.Compare(encapsulatedContent, request.Data.DocumentSOD.EncapsulatedContent) != 0 {
		api.Log(r).WithFields(logan.F{
			"encapsulated_content_new": encapsulatedContent,
			"encapsulated_content_old": request.Data.DocumentSOD.EncapsulatedContent,
		}).Info("encapsulated content update")
		request.Data.DocumentSOD.EncapsulatedContent = encapsulatedContent
	}

	return request, nil
}

// PrependPrefix - сrunch before Android fix
func PrependPrefix(data string) string {
	// Parse by VERSION field
	subs := strings.Split(data, "0201")

	dataLength := subs[0]

	// recreate the rest of the string without length
	rest := "0201" + strings.Join(subs[1:], "0201")

	restByteLen := int64(len(rest) / 2)

	actualLength := toHex(restByteLen)

	if restByteLen > 128 && restByteLen < 256 {
		actualLength = "81" + actualLength
	}
	if restByteLen > 256 {
		actualLength = "82" + actualLength
	}

	data = "30" + dataLength + rest
	if strings.Compare(dataLength, actualLength) != 0 {
		data = "30" + actualLength + rest
	}

	return data
}

func toHex(number int64) string {
	hexStr := strconv.FormatInt(number, 16)
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}

	return hexStr
}
