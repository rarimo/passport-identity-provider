package zknullifiers

import (
	"os"

	"github.com/iden3/go-rapidsnark/prover"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/verifier"
	"github.com/iden3/go-rapidsnark/witness"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

const (
	wasmFilePath            = "assets/nullifiers_counter.wasm"
	zkeyFilePath            = "assets/nullifiers_counter.zkey"
	verificationKeyFilePath = "assets/nullifiers_counter_verification_key.json"
)

type Prover interface {
	GenerateZKProof(inputs map[string]interface{}) (*types.ZKProof, error)
	VerifyZKProof(proof types.ZKProof) error
}

type nullifiersProver struct {
	calculator      *witness.Circom2WitnessCalculator
	zkey            []byte
	verificationKey []byte
}

func New() (Prover, error) {
	var zkProver nullifiersProver
	var err error

	wasmBytes, err := os.ReadFile(wasmFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read WASM file", logan.F{
			"file": wasmFilePath,
		})
	}

	zkProver.calculator, err = witness.NewCircom2WitnessCalculator(wasmBytes, true)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create witness calculator")
	}

	zkProver.zkey, err = os.ReadFile(zkeyFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read zkey file", logan.F{
			"file": zkeyFilePath,
		})
	}

	zkProver.verificationKey, err = os.ReadFile(verificationKeyFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read verification key file", logan.F{
			"file": verificationKeyFilePath,
		})
	}

	return &zkProver, nil
}

func (np *nullifiersProver) GenerateZKProof(inputs map[string]interface{}) (*types.ZKProof, error) {
	binaryWitness, err := np.calculator.CalculateWTNSBin(inputs, false)
	if err != nil {
		return nil, errors.Wrap(err, "failed to calculate binary witness")
	}

	proof, err := prover.Groth16Prover(np.zkey, binaryWitness)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create zk proof")
	}

	if err = np.VerifyZKProof(*proof); err != nil {
		return nil, errors.Wrap(err, "failed to verify zk proof")
	}

	return proof, nil
}

func (np *nullifiersProver) VerifyZKProof(proof types.ZKProof) error {
	if err := verifier.VerifyGroth16(proof, np.verificationKey); err != nil {
		return errors.Wrap(err, "failed to verify groth16 proof")
	}

	return nil
}
