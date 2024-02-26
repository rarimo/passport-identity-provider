package config

import (
	"fmt"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"gitlab.com/distributed_lab/figure"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
	"gitlab.com/distributed_lab/logan/v3/errors"
	"reflect"
)

type IssuerConfiger interface {
	IssuerConfig() *IssuerConfig
}

type IssuerConfig struct {
	BaseUrl          string   `fig:"base_url,required"`
	DID              *w3c.DID `fig:"did,required"`
	ClaimType        string   `fig:"claim_type,required"`
	CredentialSchema string   `fig:"credential_schema,required"`
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
			With(figure.BaseHooks, iden3Hooks).
			From(kv.MustGetStringMap(i.getter, "issuer")).
			Please()
		if err != nil {
			panic(err)
		}

		return &result
	}).(*IssuerConfig)
}

var iden3Hooks = figure.Hooks{
	"*w3c.DID": func(value interface{}) (reflect.Value, error) {
		switch v := value.(type) {
		case string:
			did, err := w3c.ParseDID(v)
			if err != nil {
				return reflect.Value{}, errors.Wrap(err, "failed to parse DID")
			}
			return reflect.ValueOf(did), nil
		case nil:
			return reflect.ValueOf(nil), nil
		default:
			return reflect.Value{}, fmt.Errorf("unsupported conversion from %T", value)
		}
	},
}
