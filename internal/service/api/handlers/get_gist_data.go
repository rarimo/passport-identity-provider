package handlers

import (
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/iden3/contracts-abi/state/go/abi"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/rarimo/passport-identity-provider/internal/service/api/requests"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

func GetGistData(w http.ResponseWriter, r *http.Request) {
	req, err := requests.NewGetGistDataRequest(r)
	if err != nil {
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	userDID, err := w3c.ParseDID(req.UserDID)
	if err != nil {
		Log(r).WithError(err).Error("failed to parse user DID")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	userID, err := core.IDFromDID(*userDID)
	if err != nil {
		Log(r).WithError(err).Error("failed to parse user ID")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	stateContract := StateContract(r)

	gistProof, err := stateContract.GetGISTProof(&bind.CallOpts{}, userID.BigInt())
	if err != nil {
		Log(r).WithError(err).Error("failed to get GIST proof")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	gistRoot, err := stateContract.GetGISTRoot(&bind.CallOpts{})
	if err != nil {
		Log(r).WithError(err).Error("failed to get GIST root")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	response := newGistDataResponse(req.UserDID, gistProof, gistRoot)

	ape.Render(w, response)
}

func newGistDataResponse(userDID string, proof abi.IStateGistProof, root *big.Int) resources.GistDataResponse {
	siblings := make([]string, len(proof.Siblings))
	for i, sibling := range proof.Siblings {
		siblings[i] = sibling.String()
	}

	return resources.GistDataResponse{
		Data: resources.GistData{
			Key: resources.Key{
				ID:   userDID,
				Type: resources.GIST_DATAS,
			},
			Attributes: resources.GistDataAttributes{
				GistRoot: root.String(),
				GistProof: resources.GistProof{
					Root:         proof.Root.String(),
					Existence:    proof.Existence,
					Siblings:     siblings,
					Index:        proof.Index.String(),
					Value:        proof.Value.String(),
					AuxExistence: proof.AuxExistence,
					AuxIndex:     proof.AuxIndex.String(),
					AuxValue:     proof.AuxValue.String(),
				},
			},
		},
		Included: resources.Included{},
	}
}
