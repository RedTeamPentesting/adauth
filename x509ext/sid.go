package x509ext

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

var (
	NTDSCASecurityExtOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2}
	NTDSObjectSIDOID     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2, 1}
)

// NewNTDSCaSecurityExt creates a szOID_NTDS_CA_SECURITY_EXT extension that
// contains a SID. See
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/e563cff8-1af6-4e6f-a655-7571ca482e71.
func NewNTDSCaSecurityExt(sid string) (ext pkix.Extension, err error) {
	ext.Id = NTDSCASecurityExtOID

	idBytes, err := asn1.Marshal(NTDSObjectSIDOID)
	if err != nil {
		return ext, fmt.Errorf("marshal SID OID: %w", err)
	}

	rawSIDBytes, err := asn1.Marshal([]byte(sid))
	if err != nil {
		return ext, fmt.Errorf("marshal SID: %w", err)
	}

	sidBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Bytes:      rawSIDBytes,
	})
	if err != nil {
		return ext, fmt.Errorf("wrap marshalled SID: %w", err)
	}

	extBytes, err := asn1.Marshal([]asn1.RawValue{
		{
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Bytes:      append(idBytes, sidBytes...),
		},
	})
	if err != nil {
		return ext, fmt.Errorf("marshal extension bytes: %w", err)
	}

	ext.Value = append(ext.Value, extBytes...)

	return ext, nil
}

// SID retrieves the SID from the szOID_NTDS_CA_SECURITY_EXT extension and an
// empty string with no error when the extension is not present.
func SID(cert *x509.Certificate) (string, error) {
	for _, extension := range append(cert.Extensions, cert.ExtraExtensions...) {
		if !extension.Id.Equal(NTDSCASecurityExtOID) {
			continue
		}

		return SIDFromExtension(extension)
	}

	return "", nil
}

// SID retrieves the SID from the szOID_NTDS_CA_SECURITY_EXT extension.
func SIDFromExtension(ext pkix.Extension) (string, error) {
	var rawExtensions []asn1.RawValue

	_, err := asn1.Unmarshal(ext.Value, &rawExtensions)
	if err != nil {
		return "", fmt.Errorf("unmarshal extension structure: %w", err)
	}

	if len(rawExtensions) != 1 {
		return "", fmt.Errorf("parsed %d raw values instead of 1", len(rawExtensions))
	}

	rawExtension := rawExtensions[0]

	var id asn1.ObjectIdentifier

	rest, err := asn1.Unmarshal(rawExtension.Bytes, &id)
	if err != nil {
		return "", fmt.Errorf("unmarshal SID OID: %w", err)
	}

	if !id.Equal(NTDSObjectSIDOID) {
		return "", fmt.Errorf("SID OID is %s instead of %s", id, NTDSObjectSIDOID)
	}

	var sidStructure asn1.RawValue

	_, err = asn1.Unmarshal(rest, &sidStructure)
	if err != nil {
		return "", fmt.Errorf("unmarshal SID structure: %w", err)
	}

	var sidBytes []byte

	_, err = asn1.Unmarshal(sidStructure.Bytes, &sidBytes)
	if err != nil {
		return "", fmt.Errorf("unmarshal SID: %w", err)
	}

	return string(sidBytes), nil
}
