package config

import (
	"gitlab.com/distributed_lab/figure/v3"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
	"os"
)

type VerifierConfiger interface {
	VerifierConfig() *VerifierConfig
}

type VerifierConfig struct {
	VerificationKey []byte
	MasterCerts     []byte
	AllowedAge      int
}

type verifier struct {
	once   comfig.Once
	getter kv.Getter
}

func NewVerifierConfiger(getter kv.Getter) VerifierConfiger {
	return &verifier{
		getter: getter,
	}
}

func (v *verifier) VerifierConfig() *VerifierConfig {
	return v.once.Do(func() interface{} {
		newCfg := struct {
			VerificationKeyPath string `fig:"verification_key_path,required"`
			MasterCertsPath     string `fig:"master_certs_path,required"`
			AllowedAge          int    `fig:"allowed_age,required"`
		}{}

		err := figure.
			Out(&newCfg).
			From(kv.MustGetStringMap(v.getter, "verifier")).
			Please()
		if err != nil {
			panic(err)
		}

		verificationKey, err := os.ReadFile(newCfg.VerificationKeyPath)
		if err != nil {
			panic(err)
		}

		masterCerts, err := os.ReadFile(newCfg.MasterCertsPath)
		if err != nil {
			panic(err)
		}

		return &VerifierConfig{
			VerificationKey: verificationKey,
			MasterCerts:     masterCerts,
			AllowedAge:      newCfg.AllowedAge,
		}
	}).(*VerifierConfig)
}
