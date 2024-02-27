package vault

import (
	"context"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/rarimo/passport-identity-provider/internal/config"
	"gitlab.com/distributed_lab/figure/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
	"math/big"
)

const (
	vaultMountPath    = "secret"
	vaultIssuerPath   = "issuer"
	vaultVerifierPath = "verifier"
)

type VaultClient struct {
	client *vaultapi.Client
}

func NewVaultClient(config *config.VaultConfig) (*VaultClient, error) {
	conf := vaultapi.DefaultConfig()
	conf.Address = config.Address

	client, err := vaultapi.NewClient(conf)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize new client")
	}

	client.SetToken(config.Token)

	return &VaultClient{client: client}, nil
}

func (v *VaultClient) IssuerAuthData() (string, string, error) {
	conf := struct {
		IssuerLogin    string `fig:"login,required"`
		IssuerPassword string `fig:"password,required"`
	}{}

	secret, err := v.client.KVv2(vaultMountPath).Get(context.Background(), vaultIssuerPath)
	if err != nil {
		return "", "", errors.Wrap(err, "failed to get secret")
	}

	if err := figure.
		Out(&conf).
		With(figure.BaseHooks).
		From(secret.Data).
		Please(); err != nil {
		return "", "", errors.Wrap(err, "failed to figure out")
	}

	return conf.IssuerLogin, conf.IssuerPassword, nil
}

func (v *VaultClient) Blinder() (*big.Int, error) {
	conf := struct {
		Blinder string `fig:"blinder,required"`
	}{}

	secret, err := v.client.KVv2(vaultMountPath).Get(context.Background(), vaultVerifierPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get secret")
	}

	if err := figure.
		Out(&conf).
		With(figure.BaseHooks).
		From(secret.Data).
		Please(); err != nil {
		return nil, errors.Wrap(err, "failed to figure out")
	}

	blinder, ok := new(big.Int).SetString(conf.Blinder, 10)
	if !ok {
		return nil, errors.New("failed to set string to big.Int")
	}

	return blinder, nil
}
