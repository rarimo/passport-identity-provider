package handlers

import (
	"math/big"
	"net/http"

	"github.com/iden3/go-rapidsnark/types"
	"github.com/rarimo/passport-identity-provider/internal/data"
	"github.com/rarimo/passport-identity-provider/internal/data/pg"
	"github.com/rarimo/passport-identity-provider/internal/service/api"
	"github.com/rarimo/passport-identity-provider/internal/service/api/requests"
	"github.com/rarimo/passport-identity-provider/internal/zknullifiers"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
	"gitlab.com/distributed_lab/kit/pgdb"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

func GetUniquenessProofs(w http.ResponseWriter, r *http.Request) {
	req, err := requests.NewGetUniquenessProofRequest(r)
	if err != nil {
		api.Log(r).WithError(err).Error("failed to parse get uniqueness proof request")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	_, uniqueClaims, err := getUniqueClaims(r, req)
	if err != nil {
		api.Log(r).WithError(err).Error("failed to select unique claims")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	var (
		blinder *big.Int
		proofs  = make([]*types.ZKProof, len(uniqueClaims))
	)

	blinder, err = api.VaultClient(r).Blinder()
	if err != nil {
		api.Log(r).WithError(err).Error("failed to get blinder from the vault")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	for i := range uniqueClaims {
		documentHash, ok := new(big.Int).SetString(uniqueClaims[i].DocumentHash, 10)
		if !ok {
			api.Log(r).WithField("document_hash", uniqueClaims[i].DocumentHash).WithError(err).Error("failed to parse document hash")
			ape.RenderErr(w, problems.InternalError())
			return
		}

		proofs[i], err = buildNullifiersCounterProf(r, documentHash, blinder)
		if err != nil {
			api.Log(r).WithError(err).Error("failed to build nullifiers counter proof")
			ape.RenderErr(w, problems.InternalError())
			return
		}
	}

	ape.Render(w, newUniquenessProofResponse(r, req.OffsetPageParams, proofs))
}

func getUniqueClaims(r *http.Request, req requests.GetUniquenessProofRequest) (amount int, claims []data.Claim, err error) {
	amount, err = api.MasterQ(r).
		Claim().
		DistinctOn(pg.DocumentHashColumn).
		GroupBy(pg.DocumentHashColumn).
		Count()
	if err != nil {
		return 0, nil, errors.Wrap(err, "failed to count unique claims")
	}

	claims, err = api.MasterQ(r).
		Claim().
		DistinctOn(pg.DocumentHashColumn).
		Page(req.OffsetPageParams, pg.DocumentHashColumn).
		Select()
	if err != nil {
		return 0, nil, errors.Wrap(err, "failed to select unique claims")
	}

	return amount, claims, nil
}

func buildNullifiersCounterProf(r *http.Request, documentHash, blinder *big.Int) (*types.ZKProof, error) {
	claims, err := api.MasterQ(r).Claim().FilterBy(pg.DocumentHashColumn, documentHash.String()).Select()
	if err != nil {
		return nil, errors.Wrap(err, "failed to select claims", logan.F{"document_hash": documentHash.String()})
	}

	var (
		ok    bool
		salts = make([]*big.Int, len(claims))
	)

	for i := range claims {
		salts[i], ok = new(big.Int).SetString(claims[i].Salt, 10)
		if !ok {
			return nil, errors.Wrap(err, "failed to parse salt", logan.F{"salt": claims[i].Salt})
		}
	}

	inputs, err := zknullifiers.CreateInputs(api.ProverCfg(r).NullifiersCount, api.ProverCfg(r).TreeDepth, blinder, documentHash, salts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create inputs", logan.F{
			"document_hash": documentHash.String(),
		})
	}

	proof, err := api.NullifiersProver(r).GenerateZKProof(inputs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate zk proof", inputs)
	}

	return proof, nil
}

func newUniquenessProofResponse(r *http.Request, pageParams pgdb.OffsetPageParams, proofs []*types.ZKProof) resources.UniquenessProofListResponse {
	uniquenessProofs := make([]resources.UniquenessProof, len(proofs))

	for i, proof := range proofs {
		uniquenessProofs[i] = newUniquenessProof(proof)
	}

	return resources.UniquenessProofListResponse{
		Data:  uniquenessProofs,
		Links: data.GetOffsetLinks(r, pageParams),
	}
}

func newUniquenessProof(proof *types.ZKProof) resources.UniquenessProof {
	return resources.UniquenessProof{
		Key: resources.Key{
			Type: resources.UNIQUENESS_PROOF,
		},
		Attributes: resources.UniquenessProofAttributes{
			Proof: proof,
		},
	}
}
