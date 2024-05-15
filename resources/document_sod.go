package resources

import "encoding/asn1"

type DigestAttribute struct {
	ID     asn1.ObjectIdentifier
	Digest []asn1.RawValue `asn1:"set"`
}

type EncapsulatedData struct {
	Version             int
	PrivateKeyAlgorithm asn1.RawValue
	PrivateKey          asn1.RawValue
}

type PrivateKeyElement struct {
	Integer  int
	OctetStr asn1.RawValue
}
