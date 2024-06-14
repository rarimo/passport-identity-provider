package zknullifiers

import (
	"encoding/json"
	"math"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/witness"
	"github.com/wealdtech/go-merkletree/v2"
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

func CreateInputs(nullifiersCount, treeDepth int, blinder, documentHash *big.Int, salts []*big.Int) (map[string]interface{}, error) {
	leaves := make([][]byte, nullifiersCount)
	for i := 0; i < nullifiersCount; i++ {
		if i > len(salts)-1 {
			leaves[i] = []byte{0}
			continue
		}

		nullifier, err := poseidon.Hash([]*big.Int{documentHash, blinder, salts[i]})
		if err != nil {
			return nil, errors.Wrap(err, "failed to create nullifier")
		}

		leaves[i] = nullifier.Bytes()
	}

	root, proofs, err := getMTProofs(treeDepth, leaves)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get merkle proofs")
	}

	inputs := Inputs{
		Root:           root,
		Blinder:        blinder.String(),
		DocumentHash:   documentHash.String(),
		Salt:           make([]string, nullifiersCount),
		ProofsBranches: make([][]string, nullifiersCount),
		ProofsOrder:    make([][]string, nullifiersCount),
	}

	for i, proof := range proofs {
		inputs.ProofsBranches[i] = proof.Siblings
		inputs.ProofsOrder[i] = proof.Orders

		if i > len(salts)-1 {
			inputs.Salt[i] = "0"
			continue
		}

		inputs.Salt[i] = salts[i].String()
	}

	rawInputs, err := json.Marshal(inputs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal inputs")
	}

	return witness.ParseInputs(rawInputs)
}

func getMTProofs(treeDepth int, leaves [][]byte) (string, []MtProof, error) {
	oldLength := len(leaves)

	// crunch to build fixed-sized tree by filling extra values with zeroes
	dataAmount := int(math.Pow(2, float64(treeDepth)))
	for i := len(leaves); i < dataAmount; i++ {
		leaves = append(leaves, []byte{0})
	}

	tree, err := merkletree.NewTree(merkletree.WithData(leaves), merkletree.WithHashType(NewPoseidon()))
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to create merkle tree")
	}

	proofs := make([]MtProof, oldLength)

	for i := 0; i < oldLength; i++ {
		proof, err := tree.GenerateProof(leaves[i], 0)
		if err != nil {
			return "", nil, errors.Wrap(err, "failed to generate merkle tree proof")
		}

		proofs[i] = buildBranch(leaves[i], proof)
	}

	return new(big.Int).SetBytes(tree.Root()).String(), proofs, nil
}

func buildBranch(leaf []byte, proof *merkletree.Proof) MtProof {
	var (
		branch    MtProof
		hasher    = NewPoseidon()
		proofHash = hasher.Hash(leaf)
		index     = proof.Index + (1 << uint(len(proof.Hashes)))
	)

	for k := 0; k < len(proof.Hashes); k++ {
		branch.Siblings = append(branch.Siblings, new(big.Int).SetBytes(proof.Hashes[k]).String())

		if index%2 == 0 {
			proofHash = hasher.Hash(proofHash, proof.Hashes[k])
			branch.Orders = append(branch.Orders, "0")
			index >>= 1
			continue
		}

		proofHash = hasher.Hash(proof.Hashes[k], proofHash)
		branch.Orders = append(branch.Orders, "1")
		index >>= 1
	}

	return branch
}
