package service

import (
	"github.com/go-chi/chi"
	"github.com/rarimo/passport-identity-provider/internal/data/pg"
	"github.com/rarimo/passport-identity-provider/internal/service/api/handlers"
	"github.com/rarimo/passport-identity-provider/internal/service/issuer"
	"gitlab.com/distributed_lab/ape"
)

func (s *service) router() chi.Router {
	r := chi.NewRouter()

	r.Use(
		ape.RecoverMiddleware(s.log),
		ape.LoganMiddleware(s.log),
		ape.CtxMiddleware(
			handlers.CtxLog(s.log),
			handlers.CtxVerifierConfig(s.cfg.VerifierConfig()),
			handlers.CtxIssuer(issuer.New(
				s.cfg.Log().WithField("service", "issuer"),
				s.cfg.IssuerConfig(),
			)),
			handlers.CtxProofsQ(pg.NewProofsQ(s.cfg.DB())),
		),
	)
	r.Route("/integrations/identity-provider-service", func(r chi.Router) {
		r.Route("/v1", func(r chi.Router) {
			r.Post("/create-identity", handlers.CreateIdentity)
		})
	})

	return r
}
