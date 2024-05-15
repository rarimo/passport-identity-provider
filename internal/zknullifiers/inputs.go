package zknullifiers

import (
	"encoding/json"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/witness"
	"github.com/wealdtech/go-merkletree/v2"
	mtposeidon "github.com/wealdtech/go-merkletree/v2/poseidon"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type Inputs struct {
	Blinder        string     `json:"blinder"`
	DocumentHash   string     `json:"documentHash"`
	Salt           []string   `json:"salt"`
	Root           string     `json:"root"`
	ProofsOrder    [][]string `json:"proofsOrder"`
	ProofsBranches [][]string `json:"proofsBranches"`
}

type MtProof struct {
	Siblings []string
	Orders   []string
}

func CreateInputs(blinder, documentHash *big.Int, salts []*big.Int) (map[string]interface{}, error) {
	leaves := make([][]byte, len(salts))
	for i, salt := range salts {
		nullifier, err := poseidon.Hash([]*big.Int{documentHash, blinder, salt})
		if err != nil {
			return nil, errors.Wrap(err, "failed to create nullifier")
		}

		leaves[i] = nullifier.Bytes()
	}

	root, proofs, err := getMTProofs(leaves)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get merkle proofs")
	}

	inputs := Inputs{
		Root:           root,
		Blinder:        blinder.String(),
		DocumentHash:   documentHash.String(),
		Salt:           make([]string, len(proofs)),
		ProofsBranches: make([][]string, len(proofs)),
		ProofsOrder:    make([][]string, len(proofs)),
	}

	for i, proof := range proofs {
		inputs.Salt[i] = salts[i].String()
		inputs.ProofsBranches[i] = proof.Siblings
		inputs.ProofsOrder[i] = proof.Orders
	}

	rawInputs, err := json.Marshal(inputs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal inputs")
	}

	return witness.ParseInputs(rawInputs)
}

func getMTProofs(leaves [][]byte) (string, []MtProof, error) {
	tree, err := merkletree.NewTree(merkletree.WithData(leaves), merkletree.WithHashType(mtposeidon.New()))
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to create merkle tree")
	}

	proofs := make([]MtProof, len(leaves))

	for i, leaf := range leaves {
		res := MtProof{}

		proof, err := tree.GenerateProof(leaf, 0)
		if err != nil {
			return "", nil, errors.Wrap(err, "failed to generate merkle tree proof")
		}

		for _, hash := range proof.Hashes {
			res.Siblings = append(res.Siblings, new(big.Int).SetBytes(hash).String())
		}
		res.Orders = buildOrders(leaf, proof, mtposeidon.New())

		proofs[i] = res
	}

	return new(big.Int).SetBytes(tree.Root()).String(), proofs, nil
}

func buildOrders(data []byte, proof *merkletree.Proof, hashType merkletree.HashType) []string {
	resp := make([]string, len(proof.Hashes))
	var proofHash = data
	index := proof.Index + (1 << uint(len(proof.Hashes)))

	for i, hash := range proof.Hashes {
		if index%2 == 0 {
			proofHash = hashType.Hash(proofHash, hash)
			resp[i] = "0"
		} else {
			proofHash = hashType.Hash(hash, proofHash)
			resp[i] = "1"
		}
		index >>= 1
	}

	return resp
}
