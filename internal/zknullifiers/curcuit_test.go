package zknullifiers

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/iden3/go-rapidsnark/types"
	"github.com/stretchr/testify/assert"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

var (
	documentHash, _ = new(big.Int).SetString("8302794276508657323125842252912847046623971092627426530323130710715455910928", 10)
	blinder, _      = new(big.Int).SetString("11714559926329488462499858375762588794276508657368433057518712516415455910929", 10)
	salt1, _        = new(big.Int).SetString("55910928", 10)
	salt2, _        = new(big.Int).SetString("58422529128", 10)
	salt3, _        = new(big.Int).SetString("6258879427650865736", 10)
	salt4, _        = new(big.Int).SetString("5599263", 10)
)

const rawValidInputs = `{"blinder":11714559926329488462499858375762588794276508657368433057518712516415455910929,"documentHash":8302794276508657323125842252912847046623971092627426530323130710715455910928,"proofsBranches":[[14608654625794963586448227673575985341169574701931235311695964667515136442289,14251024860076613042921893745958981824974577945853564226868633391418705231824],[14956400568832893264463752969297624636961411789737111255032868037575924055015,14251024860076613042921893745958981824974577945853564226868633391418705231824],[15786718725042124006503955346891945541263064496327370271144286596393510010204,18429428004424288136854689676374984841037963087622002096815542450018113160566],[4554524831031135169141095118682810348362568316467552620599541134110663353784,18429428004424288136854689676374984841037963087622002096815542450018113160566]],"proofsOrder":[[0,0],[1,0],[0,1],[1,1]],"root":14455125453068568951440238152987304090154352684894597083022717377037819367009,"salt":[55910928,58422529128,6258879427650865736,5599263]}`

func TestValidCreateInputs(t *testing.T) {
	inputs, err := CreateInputs(blinder, documentHash, []*big.Int{salt1, salt2, salt3, salt4})
	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to create inputs"))
	}

	rawInputs, _ := json.Marshal(inputs)

	assert.Equal(t, rawValidInputs, string(rawInputs))
}

func TestInvalidCreateInputs(t *testing.T) {
	inputs, err := CreateInputs(blinder, documentHash, []*big.Int{salt2, salt2, salt1, salt4})
	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to create inputs"))
	}

	rawInputs, _ := json.Marshal(inputs)

	assert.NotEqual(t, rawValidInputs, string(rawInputs))
}

func TestValidProof(t *testing.T) {
	prover, err := New()
	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to create new zknullifier prover"))
	}

	inputs, err := CreateInputs(blinder, documentHash, []*big.Int{salt1, salt2, salt3, salt4})
	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to create inputs"))
	}

	zkProof, err := prover.GenerateZKProof(inputs)
	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to generate zk proof"))
	}

	fmt.Println("zk proof", zkProof.Proof, zkProof.PubSignals)

	if err = prover.VerifyZKProof(*zkProof); err != nil {
		t.Fatal(errors.Wrap(err, "failed to verify zk proof"))
	}
}

func TestInvalidProof(t *testing.T) {
	const rawProof = `{
            "proof": {
                "curve": "bn128",
                "pi_a": [
                    "13459767366859018704659679610323414163327547413693059400948753304150544807481",
                    "10001351299744725753388223500045085032583668265106436158447667205865394620653",
                    "1"
                ],
                "pi_b": [
                    [
                        "1944194063076802549119538877441990336600059056469354543623351420333711976233",
                        "7149503782492798279846515409564853398434243389244660028207281104837744591186"
                    ],
                    [
                        "3579682984284958531775661824083721608436340705727675798688403220966829440946",
                        "19617098805401930033415145789761418627899923413996526631405591762244715497341"
                    ],
                    [
                        "1",
                        "0"
                    ]
                ],
                "pi_c": [
                    "3651080770076470185802195250443912733161249787060599524751506768818372836304",
                    "7934689461922693190582375200805572608066902814583094551841607496620624557817",
                    "1"
                ],
                "protocol": "groth16"
            },
            "pub_signals": [
                "311829949927574718572524671081106490489",
                "125712886666704113030568989702153193884",
                "4903594"
            ]
        }`

	var zkProof types.ZKProof
	if err := json.Unmarshal([]byte(rawProof), &zkProof); err != nil {
		t.Fatal(errors.Wrap(err, "failed to unmarshal zk proof"))
	}

	prover, err := New()
	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to create new zknullifier prover"))
	}

	assert.NotNil(t, prover.VerifyZKProof(zkProof))
}
