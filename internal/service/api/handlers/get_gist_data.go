package handlers

import (
	"context"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/iden3/contracts-abi/state/go/abi"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/rarimo/passport-identity-provider/internal/service/api/requests"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

func GetGistData(w http.ResponseWriter, r *http.Request) {
	req, err := requests.NewGetGistDataRequest(r)
	if err != nil {
		Log(r).WithError(err).Error("failed to parse get gist data request")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	log := Log(r).WithFields(logan.F{
		"user-agent":   r.Header.Get("User-Agent"),
		"user_did":     req.UserDID,
		"block_number": req.BlockNumber,
	})

	userDID, err := w3c.ParseDID(req.UserDID)
	if err != nil {
		log.WithError(err).Error("failed to parse user DID")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	userID, err := core.IDFromDID(*userDID)
	if err != nil {
		log.WithError(err).Error("failed to parse user ID")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	blockNum, err := EthClient(r).BlockNumber(context.Background())
	if err != nil {
		log.WithError(err).Error("failed to get block number")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	if req.BlockNumber > blockNum {
		log.WithFields(logan.F{
			"latest_block_number": blockNum,
		}).Error("Requested block number is higher than latest")
		ape.RenderErr(w, problems.BadRequest(validation.Errors{
			"/block_number": errors.New("Requested block number is higher than latest"),
		})...)
		return
	}

	if req.BlockNumber != 0 {
		blockNum = req.BlockNumber
	}

	stateContract := StateContract(r)

	gistProof, err := stateContract.GetGISTProof(&bind.CallOpts{
		BlockNumber: new(big.Int).SetUint64(blockNum),
	}, userID.BigInt())
	if err != nil {
		log.WithError(err).Error("failed to get GIST proof")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	gistRoot, err := stateContract.GetGISTRoot(&bind.CallOpts{
		BlockNumber: new(big.Int).SetUint64(blockNum),
	})
	if err != nil {
		log.WithError(err).Error("failed to get GIST root")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	if gistProof.Root.Cmp(gistRoot) != 0 {
		log.WithFields(logan.F{
			"gist_root":       gistRoot.String(),
			"gist_proof_root": gistProof.Root.String(),
		}).Warn("gist root does not match")
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
