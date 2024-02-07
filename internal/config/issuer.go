package config

import (
	"gitlab.com/distributed_lab/figure"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
)

type IssuerConfiger interface {
	IssuerConfig() *IssuerConfig
}

type IssuerConfig struct {
	BaseUrl          string `fig:"base_url,required"`
	AuthUsername     string `fig:"auth_username,required"`
	AuthPassword     string `fig:"auth_password,required"`
	ClaimType        string `fig:"claim_type,required"`
	CredentialSchema string `fig:"credential_schema,required"`
}

type issuer struct {
	once   comfig.Once
	getter kv.Getter
}

func NewIssuerConfiger(getter kv.Getter) IssuerConfiger {
	return &issuer{
		getter: getter,
	}
}

func (i *issuer) IssuerConfig() *IssuerConfig {
	return i.once.Do(func() interface{} {
		var result IssuerConfig

		err := figure.
			Out(&result).
			From(kv.MustGetStringMap(i.getter, "issuer")).
			Please()
		if err != nil {
			panic(err)
		}

		return &result
	}).(*IssuerConfig)
}
