package pg

import (
	"database/sql"
	"errors"

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
	claimsCounter  = sq.Select("COUNT(*) AS count").From(claimsTableName)
)

func NewClaimsQ(db *pgdb.DB) data.ClaimQ {
	return &claimsQ{
		db:    db,
		sel:   claimsSelector,
		upd:   claimsUpdate,
		count: claimsCounter,
	}
}

type claimsQ struct {
	db    *pgdb.DB
	sel   sq.SelectBuilder
	upd   sq.UpdateBuilder
	count sq.SelectBuilder
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

func (q *claimsQ) Update(value data.Claim) error {
	clauses := structs.Map(value)
	stmt := q.upd.SetMap(clauses)
	err := q.db.Exec(stmt)
	return err
}

func (q *claimsQ) FilterBy(column string, value any) data.ClaimQ {
	eq := sq.Eq{column: value}
	q.sel = q.sel.Where(eq)
	q.upd = q.upd.Where(eq)
	q.count = q.count.Where(eq)
	return q
}

func (q *claimsQ) Get() (*data.Claim, error) {
	var result data.Claim
	err := q.db.Get(&result, q.sel)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &result, err
}

func (q *claimsQ) Select() ([]data.Claim, error) {
	var result []data.Claim
	err := q.db.Select(&result, q.sel)
	return result, err
}

func (q *claimsQ) Count() (int, error) {
	var result struct {
		Count int `db:"count"`
	}
	err := q.db.Get(&result, q.count)
	return result.Count, err
}

func (q *claimsQ) DeleteByID(id uuid.UUID) error {
	if err := q.db.Exec(sq.Delete(claimsTableName).Where(sq.Eq{"id": id})); err != nil {
		return err
	}
	return nil
}

func (q *claimsQ) ForUpdate() data.ClaimQ {
	q.sel = q.sel.Suffix("FOR UPDATE")
	return q
}

func (q *claimsQ) ResetFilter() data.ClaimQ {
	q.sel = claimsSelector
	q.upd = claimsUpdate
	q.count = claimsCounter
	return q
}
