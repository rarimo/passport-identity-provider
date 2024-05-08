package config

import (
	"os"
	"time"

	"gitlab.com/distributed_lab/figure/v3"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
)

type VerifierConfiger interface {
	VerifierConfig() *VerifierConfig
}

type VerifierConfig struct {
	VerificationKeys    map[string][]byte
	MasterCerts         []byte
	AllowedAge          int
	RegistrationTimeout time.Duration
	MultiAccMinLimit    int
	MultiAccMaxLimit    int
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
			VerificationKeysPaths map[string]string `fig:"verification_keys_paths,required"`
			MasterCertsPath       string            `fig:"master_certs_path,required"`
			AllowedAge            int               `fig:"allowed_age,required"`
			MultiAccMinLimit      int               `fig:"multi_acc_min_limit,required"`
			MultiAccMaxLimit      int               `fig:"multi_acc_max_limit,required"`
			RegistrationTimeout   time.Duration     `fig:"registration_timeout"`
		}{}

		err := figure.
			Out(&newCfg).
			With(figure.BaseHooks).
			From(kv.MustGetStringMap(v.getter, "verifier")).
			Please()
		if err != nil {
			panic(err)
		}

		verificationKeys := make(map[string][]byte)
		for algo, path := range newCfg.VerificationKeysPaths {
			verificationKey, err := os.ReadFile(path)
			if err != nil {
				panic(err)
			}

			verificationKeys[algo] = verificationKey
		}

		masterCerts, err := os.ReadFile(newCfg.MasterCertsPath)
		if err != nil {
			panic(err)
		}

		return &VerifierConfig{
			VerificationKeys:    verificationKeys,
			MasterCerts:         masterCerts,
			AllowedAge:          newCfg.AllowedAge,
			MultiAccMinLimit:    newCfg.MultiAccMinLimit,
			MultiAccMaxLimit:    newCfg.MultiAccMaxLimit,
			RegistrationTimeout: newCfg.RegistrationTimeout,
		}
	}).(*VerifierConfig)
}
