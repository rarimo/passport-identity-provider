package requests

import (
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"gitlab.com/distributed_lab/kit/pgdb"
	"gitlab.com/distributed_lab/logan/v3/errors"
	"gitlab.com/distributed_lab/urlval"
)

type GetUniquenessProofRequest struct {
	pgdb.OffsetPageParams
}

func NewGetUniquenessProofRequest(r *http.Request) (GetUniquenessProofRequest, error) {
	var request GetUniquenessProofRequest

	if err := urlval.Decode(r.URL.Query(), &request); err != nil {
		return GetUniquenessProofRequest{}, validation.Errors{
			"query": errors.Wrap(err, "failed to decode query params"),
		}
	}

	//If any limit set, put 1 to give response faster
	if request.Limit == 0 {
		request.Limit = 1
	}

	return request, nil
}
