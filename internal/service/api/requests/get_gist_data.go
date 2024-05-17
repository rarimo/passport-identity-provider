package requests

import (
	"math/big"
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
	"gitlab.com/distributed_lab/urlval"
)

type GetGistDataRequest struct {
	UserDID   *w3c.DID
	StateRoot *big.Int
}

type getGistDataQuery struct {
	UserDID   string `url:"user_did"`
	StateRoot string `url:"state_root"`
}

func NewGetGistDataRequest(r *http.Request) (GetGistDataRequest, error) {
	var query getGistDataQuery

	err := urlval.Decode(r.URL.Query(), &query)
	if err != nil {
		return GetGistDataRequest{}, validation.Errors{
			"url": errors.Wrap(err, "failed to decode url"),
		}
	}

	return parseGistDataQuery(query)
}

func parseGistDataQuery(query getGistDataQuery) (GetGistDataRequest, error) {
	var (
		err error
		ok  bool
		req GetGistDataRequest
	)

	err = validation.Errors{
		"/user_did":   validation.Validate(query.UserDID, validation.Required),
		"/state_root": validation.Validate(query.StateRoot, validation.Required, is.Hexadecimal),
	}.Filter()
	if err != nil {
		return req, err
	}

	req.UserDID, err = w3c.ParseDID(query.UserDID)
	if err != nil {
		return req, validation.Errors{
			"/user_did": errors.Wrap(err, "failed to parse user DID", logan.F{
				"user_did": req.UserDID,
			}),
		}.Filter()
	}

	req.StateRoot, ok = new(big.Int).SetString(query.StateRoot, 16)
	if !ok {
		return req, validation.Errors{
			"/state_root": errors.From(errors.New("failed to parse state root"), logan.F{
				"state_root": req.StateRoot,
			}),
		}
	}

	return req, nil
}
