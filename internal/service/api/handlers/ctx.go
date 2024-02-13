package handlers

import (
	"context"
	"github.com/rarimo/passport-identity-provider/internal/config"
	"github.com/rarimo/passport-identity-provider/internal/data"
	"github.com/rarimo/passport-identity-provider/internal/service/issuer"
	"gitlab.com/distributed_lab/logan/v3"
	"net/http"
)

type ctxKey int

const (
	logCtxKey ctxKey = iota
	verifierConfigKey
	issuerCtxKey
	proofsQKey
)

func CtxLog(entry *logan.Entry) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, logCtxKey, entry)
	}
}

func Log(r *http.Request) *logan.Entry {
	return r.Context().Value(logCtxKey).(*logan.Entry)
}

func CtxVerifierConfig(entry *config.VerifierConfig) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, verifierConfigKey, entry)
	}
}

func VerifierConfig(r *http.Request) *config.VerifierConfig {
	return r.Context().Value(verifierConfigKey).(*config.VerifierConfig)
}

func CtxIssuer(iss *issuer.Issuer) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, issuerCtxKey, iss)
	}
}

func Issuer(r *http.Request) *issuer.Issuer {
	return r.Context().Value(issuerCtxKey).(*issuer.Issuer)
}

func CtxProofsQ(entry data.ProofQ) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, proofsQKey, entry)
	}
}

func ProofsQ(r *http.Request) data.ProofQ {
	return r.Context().Value(proofsQKey).(data.ProofQ).New()
}
