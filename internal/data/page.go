package data

import (
	"net/http"
	"strconv"

	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/kit/pgdb"
)

const (
	pageParamLimit  = "page[limit]"
	pageParamNumber = "page[number]"
)

func GetOffsetLinks(r *http.Request, p pgdb.OffsetPageParams) *resources.Links {
	result := resources.Links{
		Next: getOffsetLink(r, p.PageNumber+1, p.Limit),
		Self: getOffsetLink(r, p.PageNumber, p.Limit),
	}

	return &result
}

func getOffsetLink(r *http.Request, pageNumber, limit uint64) string {
	u := r.URL
	query := u.Query()
	query.Set(pageParamNumber, strconv.FormatUint(pageNumber, 10))
	query.Set(pageParamLimit, strconv.FormatUint(limit, 10))
	u.RawQuery = query.Encode()
	return u.String()
}
