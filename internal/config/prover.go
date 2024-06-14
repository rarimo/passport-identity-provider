package config

import (
	"gitlab.com/distributed_lab/figure/v3"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

const proverYamlKey = "prover"

type ProverConfiger interface {
	ProverConfig() *ProverConfig
}

type ProverConfig struct {
	NullifiersCount int `fig:"nullifiers_count,required"`
	TreeDepth       int `fig:"tree_depth,required"`
}

type prover struct {
	once   comfig.Once
	getter kv.Getter
}

func NewProverConfiger(getter kv.Getter) ProverConfiger {
	return &prover{
		getter: getter,
	}
}

func (v *prover) ProverConfig() *ProverConfig {
	return v.once.Do(func() interface{} {
		var result ProverConfig

		err := figure.
			Out(&result).
			From(kv.MustGetStringMap(v.getter, proverYamlKey)).
			Please()
		if err != nil {
			panic(errors.Wrap(err, "failed to figure out config", logan.F{"key": proverYamlKey}))
		}

		return &result
	}).(*ProverConfig)
}
