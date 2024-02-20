package handlers

import (
	"encoding/hex"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/rarimo/passport-identity-provider/internal/service/api/requests"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
	"math/big"
	"net/http"
)

func GetDocumentNullifier(w http.ResponseWriter, r *http.Request) {
	req, err := requests.NewGetDocumentNullifierRequest(r)
	if err != nil {
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	dg2HashBytes, err := hex.DecodeString(req.DG2Hash)
	if err != nil {
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	nullifierHashInput := make([]*big.Int, 0)
	if len(dg2HashBytes) >= 32 {
		// break data in a half
		nullifierHashInput = append(nullifierHashInput, new(big.Int).SetBytes(dg2HashBytes[:len(dg2HashBytes)/2]))
		nullifierHashInput = append(nullifierHashInput, new(big.Int).SetBytes(dg2HashBytes[len(dg2HashBytes)/2:]))
	} else {
		nullifierHashInput = append(nullifierHashInput, new(big.Int).SetBytes(dg2HashBytes))
	}

	nullifierHashInput = append(nullifierHashInput, VerifierConfig(r).Blinder)

	nullifierHash, err := poseidon.Hash(nullifierHashInput)
	if err != nil {
		Log(r).WithError(err).Error("failed to hash via Poseidon")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	response := resources.DocumentNullifierResponse{
		Data: resources.DocumentNullifier{
			Key: resources.Key{
				Type: resources.NULLIFIERS,
			},
			Attributes: resources.DocumentNullifierAttributes{
				DocumentNullifierHash: nullifierHash.String(),
			},
		},
	}

	ape.Render(w, response)
}
