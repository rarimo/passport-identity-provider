package config

import (
	"gitlab.com/distributed_lab/dig"
	"gitlab.com/distributed_lab/figure/v3"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
)

type VaultConfiger interface {
	VaultConfig() *VaultConfig
}

type VaultConfig struct {
	Address   string `fig:"address,required"`
	MountPath string `fig:"mount_path,required"`
	Token     string `dig:"VAULT_TOKEN,clear"`
}

type vault struct {
	once   comfig.Once
	getter kv.Getter
}

func NewVaultConfiger(getter kv.Getter) VaultConfiger {
	return &vault{
		getter: getter,
	}
}

func (v *vault) VaultConfig() *VaultConfig {
	return v.once.Do(func() interface{} {
		var result VaultConfig

		err := figure.
			Out(&result).
			From(kv.MustGetStringMap(v.getter, "vault")).
			Please()
		if err != nil {
			panic(err)
		}

		if err := dig.Out(&result).Where(map[string]interface{}{
			"address":    result.Address,
			"mount_path": result.MountPath,
		}).Now(); err != nil {
			panic(err)
		}

		return &result
	}).(*VaultConfig)
}
