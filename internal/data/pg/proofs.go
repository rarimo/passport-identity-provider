package pg

import (
	sq "github.com/Masterminds/squirrel"
	"github.com/fatih/structs"
	"github.com/rarimo/passport-identity-provider/internal/data"
	"gitlab.com/distributed_lab/kit/pgdb"
)

const proofsTableName = "proofs"

var (
	proofsSelector = sq.Select("*").From(proofsTableName)
	proofsUpdate   = sq.Update(proofsTableName)
)

func NewProofsQ(db *pgdb.DB) data.ProofQ {
	return &proofsQ{
		db:  db,
		sql: proofsSelector,
		upd: proofsUpdate,
	}
}

type proofsQ struct {
	db  *pgdb.DB
	sql sq.SelectBuilder
	upd sq.UpdateBuilder
}

func (q *proofsQ) New() data.ProofQ {
	return NewProofsQ(q.db.Clone())
}

func (q *proofsQ) Insert(value data.Proof) error {
	clauses := structs.Map(value)
	stmt := sq.Insert(proofsTableName).SetMap(clauses)
	err := q.db.Exec(stmt)
	return err
}
