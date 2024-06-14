/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

type UniquenessProof struct {
	Key
	Attributes UniquenessProofAttributes `json:"attributes"`
}
type UniquenessProofResponse struct {
	Data     UniquenessProof `json:"data"`
	Included Included        `json:"included"`
}

type UniquenessProofListResponse struct {
	Data     []UniquenessProof `json:"data"`
	Included Included          `json:"included"`
	Links    *Links            `json:"links"`
}

// MustUniquenessProof - returns UniquenessProof from include collection.
// if entry with specified key does not exist - returns nil
// if entry with specified key exists but type or ID mismatches - panics
func (c *Included) MustUniquenessProof(key Key) *UniquenessProof {
	var uniquenessProof UniquenessProof
	if c.tryFindEntry(key, &uniquenessProof) {
		return &uniquenessProof
	}
	return nil
}
