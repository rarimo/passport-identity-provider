package service

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/go-chi/chi"
	stateabi "github.com/iden3/contracts-abi/state/go/abi"
	"github.com/rarimo/passport-identity-provider/internal/data/pg"
	"github.com/rarimo/passport-identity-provider/internal/service/api/handlers"
	"github.com/rarimo/passport-identity-provider/internal/service/issuer"
	"gitlab.com/distributed_lab/ape"
)

func (s *service) router() chi.Router {
	ethCli, err := ethclient.Dial(s.cfg.NetworkConfig().EthRPC)
	if err != nil {
		s.log.WithError(err).Fatal("failed to dial connect via Ethereum RPC")
	}

	stateContract, err := stateabi.NewState(common.HexToAddress(s.cfg.NetworkConfig().StateContract), ethCli)
	if err != nil {
		s.log.WithError(err).Fatal("failed to init state contract")
	}

	r := chi.NewRouter()

	r.Use(
		ape.RecoverMiddleware(s.log),
		ape.LoganMiddleware(s.log),
		ape.CtxMiddleware(
			handlers.CtxLog(s.log),
			handlers.CtxMasterQ(pg.NewMasterQ(s.cfg.DB())),
			handlers.CtxVerifierConfig(s.cfg.VerifierConfig()),
			handlers.CtxStateContract(stateContract),
			handlers.CtxProofsQ(pg.NewProofsQ(s.cfg.DB())),
			handlers.CtxClaimsQ(pg.NewClaimsQ(s.cfg.DB())),
			handlers.CtxIssuer(issuer.New(
				s.cfg.Log().WithField("service", "issuer"),
				s.cfg.IssuerConfig(),
			)),
		),
	)
	r.Route("/integrations/identity-provider-service", func(r chi.Router) {
		r.Route("/v1", func(r chi.Router) {
			r.Post("/create-identity", handlers.CreateIdentity)
			r.Get("/gist-data", handlers.GetGistData)
			r.Get("/document-nullifier", handlers.GetDocumentNullifier)
		})
	})

	return r
}
