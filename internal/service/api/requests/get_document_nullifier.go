package requests

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"gitlab.com/distributed_lab/logan/v3/errors"
	"gitlab.com/distributed_lab/urlval"
	"net/http"
)

type GetDocumentNullifierRequest struct {
	DG2Hash string `url:"dg2_hash"`
}

func NewGetDocumentNullifierRequest(r *http.Request) (GetDocumentNullifierRequest, error) {
	var req GetDocumentNullifierRequest

	err := urlval.Decode(r.URL.Query(), &req)
	if err != nil {
		return GetDocumentNullifierRequest{}, errors.Wrap(err, "failed to decode url")
	}

	return req, validateGetDocumentNullifierRequest(req)
}

func validateGetDocumentNullifierRequest(r GetDocumentNullifierRequest) error {
	return validation.Errors{
		"/dg2_hash": validation.Validate(r.DG2Hash, validation.Required),
	}.Filter()
}
