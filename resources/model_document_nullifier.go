/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

type DocumentNullifier struct {
	Key
	Attributes DocumentNullifierAttributes `json:"attributes"`
}
type DocumentNullifierResponse struct {
	Data     DocumentNullifier `json:"data"`
	Included Included          `json:"included"`
}

type DocumentNullifierListResponse struct {
	Data     []DocumentNullifier `json:"data"`
	Included Included            `json:"included"`
	Links    *Links              `json:"links"`
}

// MustDocumentNullifier - returns DocumentNullifier from include collection.
// if entry with specified key does not exist - returns nil
// if entry with specified key exists but type or ID mismatches - panics
func (c *Included) MustDocumentNullifier(key Key) *DocumentNullifier {
	var documentNullifier DocumentNullifier
	if c.tryFindEntry(key, &documentNullifier) {
		return &documentNullifier
	}
	return nil
}
