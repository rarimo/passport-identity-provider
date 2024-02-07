/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

type Claim struct {
	Key
	Attributes ClaimAttributes `json:"attributes"`
}
type ClaimResponse struct {
	Data     Claim    `json:"data"`
	Included Included `json:"included"`
}

type ClaimListResponse struct {
	Data     []Claim  `json:"data"`
	Included Included `json:"included"`
	Links    *Links   `json:"links"`
}

// MustClaim - returns Claim from include collection.
// if entry with specified key does not exist - returns nil
// if entry with specified key exists but type or ID mismatches - panics
func (c *Included) MustClaim(key Key) *Claim {
	var claim Claim
	if c.tryFindEntry(key, &claim) {
		return &claim
	}
	return nil
}
