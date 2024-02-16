package pg

import (
	"database/sql"
	sq "github.com/Masterminds/squirrel"
	"github.com/fatih/structs"
	"github.com/google/uuid"
	"github.com/rarimo/passport-identity-provider/internal/data"
	"gitlab.com/distributed_lab/kit/pgdb"
)

const claimsTableName = "claims"

var (
	claimsSelector = sq.Select("*").From(claimsTableName)
	claimsUpdate   = sq.Update(claimsTableName)
)

func NewClaimsQ(db *pgdb.DB) data.ClaimQ {
	return &claimsQ{
		db:  db,
		sql: claimsSelector,
		upd: claimsUpdate,
	}
}

type claimsQ struct {
	db  *pgdb.DB
	sql sq.SelectBuilder
	upd sq.UpdateBuilder
}

func (q *claimsQ) New() data.ClaimQ {
	return NewClaimsQ(q.db.Clone())
}

func (q *claimsQ) Insert(value data.Claim) error {
	clauses := structs.Map(value)
	stmt := sq.Insert(claimsTableName).SetMap(clauses)
	err := q.db.Exec(stmt)
	return err
}

func (q *claimsQ) FilterBy(column string, value any) data.ClaimQ {
	q.sql = q.sql.Where(sq.Eq{column: value})
	return q
}

func (q *claimsQ) Get() (*data.Claim, error) {
	var result data.Claim
	err := q.db.Get(&result, q.sql)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &result, err
}

func (q *claimsQ) Select() ([]data.Claim, error) {
	var result []data.Claim
	err := q.db.Select(&result, q.sql)
	return result, err
}

func (q *claimsQ) DeleteByID(id uuid.UUID) error {
	if err := q.db.Exec(sq.Delete(claimsTableName).Where(sq.Eq{"id": id})); err != nil {
		return err
	}
	return nil
}

func (q *claimsQ) ForUpdate() data.ClaimQ {
	q.sql = q.sql.Suffix("FOR UPDATE")
	return q
}

func (q *claimsQ) ResetFilter() data.ClaimQ {
	q.sql = sq.Select("*").From(claimsTableName)
	q.upd = sq.Update(claimsTableName)
	return q
}
