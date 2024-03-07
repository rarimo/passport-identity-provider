package resources

import "encoding/asn1"

type DigestAttribute struct {
	ID     asn1.ObjectIdentifier
	Digest []asn1.RawValue `asn1:"set"`
}

type EncapsulatedData struct {
	Version             int
	PrivateKeyAlgorithm asn1.RawValue
	PrivateKey          struct {
		El1 struct {
			Integer  int
			OctetStr asn1.RawValue
		}
		El2 struct {
			Integer  int
			OctetStr asn1.RawValue
		}
		El3 struct {
			Integer  int
			OctetStr asn1.RawValue
		}
		El4 struct {
			Integer  int
			OctetStr asn1.RawValue
		}
		El5 struct {
			Integer  int
			OctetStr asn1.RawValue
		}
		El6 struct {
			Integer  int
			OctetStr asn1.RawValue
		}
		El7 struct {
			Integer  int
			OctetStr asn1.RawValue
		}
		El8 struct {
			Integer  int
			OctetStr asn1.RawValue
		}
	}
}
