package requests

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"gitlab.com/distributed_lab/logan/v3/errors"
	"gitlab.com/distributed_lab/urlval"
	"net/http"
)

type GetGistDataRequest struct {
	UserDID string `url:"user_did"`
}

func NewGetGistDataRequest(r *http.Request) (GetGistDataRequest, error) {
	var req GetGistDataRequest

	err := urlval.Decode(r.URL.Query(), &req)
	if err != nil {
		return GetGistDataRequest{}, errors.Wrap(err, "failed to decode url")
	}

	return req, validateGetGistDataRequest(req)
}

func validateGetGistDataRequest(r GetGistDataRequest) error {
	return validation.Errors{
		"/user_did": validation.Validate(r.UserDID, validation.Required),
	}.Filter()
}
