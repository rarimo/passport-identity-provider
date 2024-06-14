package api

import (
	"context"
	"net/http"

	"github.com/ethereum/go-ethereum/ethclient"
	stateabi "github.com/iden3/contracts-abi/state/go/abi"
	"github.com/rarimo/passport-identity-provider/internal/config"
	"github.com/rarimo/passport-identity-provider/internal/data"
	"github.com/rarimo/passport-identity-provider/internal/service/issuer"
	"github.com/rarimo/passport-identity-provider/internal/service/vault"
	"github.com/rarimo/passport-identity-provider/internal/zknullifiers"
	"gitlab.com/distributed_lab/logan/v3"
)

type ctxKey int

const (
	logCtxKey ctxKey = iota
	masterQKey
	verifierConfigKey
	stateContractKey
	issuerCtxKey
	vaultClientCtxKey
	ethClientCtxKey
	proverCfgCtxKey
	zkProverCtxKey
)

func CtxLog(entry *logan.Entry) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, logCtxKey, entry)
	}
}

func Log(r *http.Request) *logan.Entry {
	return r.Context().Value(logCtxKey).(*logan.Entry)
}

func CtxMasterQ(entry data.MasterQ) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, masterQKey, entry)
	}
}

func MasterQ(r *http.Request) data.MasterQ {
	return r.Context().Value(masterQKey).(data.MasterQ).New()
}

func CtxVerifierConfig(entry *config.VerifierConfig) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, verifierConfigKey, entry)
	}
}

func VerifierConfig(r *http.Request) *config.VerifierConfig {
	return r.Context().Value(verifierConfigKey).(*config.VerifierConfig)
}

func CtxStateContract(entry *stateabi.State) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, stateContractKey, entry)
	}
}

func StateContract(r *http.Request) *stateabi.State {
	return r.Context().Value(stateContractKey).(*stateabi.State)
}

func CtxIssuer(iss *issuer.Issuer) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, issuerCtxKey, iss)
	}
}

func Issuer(r *http.Request) *issuer.Issuer {
	return r.Context().Value(issuerCtxKey).(*issuer.Issuer)
}

func CtxVaultClient(vaultClient *vault.VaultClient) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, vaultClientCtxKey, vaultClient)
	}
}

func VaultClient(r *http.Request) *vault.VaultClient {
	return r.Context().Value(vaultClientCtxKey).(*vault.VaultClient)
}

func CtxEthClient(client *ethclient.Client) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, ethClientCtxKey, client)
	}
}

func CtxNullifiersProver(entry zknullifiers.Prover) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, zkProverCtxKey, entry)
	}
}

func NullifiersProver(r *http.Request) zknullifiers.Prover {
	return r.Context().Value(zkProverCtxKey).(zknullifiers.Prover)
}

func EthClient(r *http.Request) *ethclient.Client {
	return r.Context().Value(ethClientCtxKey).(*ethclient.Client)
}

func CtxProverCfg(entry *config.ProverConfig) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, proverCfgCtxKey, entry)
	}
}

func ProverCfg(r *http.Request) *config.ProverConfig {
	return r.Context().Value(proverCfgCtxKey).(*config.ProverConfig)
}
