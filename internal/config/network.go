package config

import (
	"gitlab.com/distributed_lab/figure"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
)

type NetworkConfiger interface {
	NetworkConfig() *NetworkConfig
}

type NetworkConfig struct {
	EthRPC        string `fig:"eth_rpc,required"`
	StateContract string `fig:"state_contract,required"`
}

type network struct {
	once   comfig.Once
	getter kv.Getter
}

func NewNetworkConfiger(getter kv.Getter) NetworkConfiger {
	return &network{
		getter: getter,
	}
}

func (i *network) NetworkConfig() *NetworkConfig {
	return i.once.Do(func() interface{} {
		var result NetworkConfig

		err := figure.
			Out(&result).
			From(kv.MustGetStringMap(i.getter, "network")).
			Please()
		if err != nil {
			panic(err)
		}

		return &result
	}).(*NetworkConfig)
}
