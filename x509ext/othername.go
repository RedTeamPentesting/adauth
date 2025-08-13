// Package othername is a minimal and incomplete implementation of the otherName SAN extension.
package x509ext

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
)

var (
	UPNOID                    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	SubjectAlternativeNameOID = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// OtherName holds an other name such as an UPN from or for a Subject
// Alternative Name extension.
type OtherName struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue
}

// NewOtherNameExtension generates an otherName extension.
func NewOtherNameExtension(names ...*OtherName) (pkix.Extension, error) {
	ext := pkix.Extension{
		Id:       SubjectAlternativeNameOID,
		Critical: false,
	}

	rawValues := make([]asn1.RawValue, 0, len(names))

	for _, name := range names {
		v := asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
		}

		id, err := asn1.Marshal(name.ID)
		if err != nil {
			return ext, fmt.Errorf("marshal oid: %w", err)
		}

		v.Bytes = append(v.Bytes, id...)

		blob, err := asn1.Marshal(name.Value)
		if err != nil {
			return ext, fmt.Errorf("marshal raw name: %w", err)
		}

		v.Bytes = append(v.Bytes, blob...)

		rawValues = append(rawValues, v)
	}

	extBytes, err := asn1.Marshal(rawValues)
	if err != nil {
		return ext, fmt.Errorf("marshal extension bytes: %w", err)
	}

	ext.Value = append(ext.Value, extBytes...)

	return ext, nil
}

// NewOtherNameExtensionFromUPNs build an otherName extension based on the provided UPNs.
func NewOtherNameExtensionFromUPNs(upns ...string) (ext pkix.Extension, err error) {
	otherNames := make([]*OtherName, 0, len(upns))

	for _, upn := range upns {
		utf8Name, err := asn1.MarshalWithParams(upn, "utf8")
		if err != nil {
			return ext, fmt.Errorf("marshal UTF8 name: %w", err)
		}

		otherNames = append(otherNames, &OtherName{
			ID: UPNOID,
			Value: asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				IsCompound: true,
				Bytes:      utf8Name,
			},
		})
	}

	return NewOtherNameExtension(otherNames...)
}

// OtherNames returns the names from the otherName extension of the provided
// certificate. If it does not contain such an extension, it will return an
// empty slice and no error.
func OtherNames(cert *x509.Certificate) ([]*OtherName, error) {
	var otherNames []*OtherName

	for _, extension := range append(cert.Extensions, cert.ExtraExtensions...) {
		if !extension.Id.Equal(SubjectAlternativeNameOID) {
			continue
		}

		ons, err := OtherNamesFromExtension(extension)
		if err != nil {
			return nil, fmt.Errorf("parse otherName data: %w", err)
		}

		otherNames = append(otherNames, ons...)
	}

	return otherNames, nil
}

// OtherNames returns the names from the otherName SAN extension.
func OtherNamesFromExtension(ext pkix.Extension) ([]*OtherName, error) {
	if !ext.Id.Equal(SubjectAlternativeNameOID) {
		return nil, fmt.Errorf("extension is %s instead of Subject Alternative Name (%s)",
			ext.Id, SubjectAlternativeNameOID)
	}

	values := []asn1.RawValue{}

	_, err := asn1.Unmarshal(ext.Value, &values)
	if err != nil {
		return nil, fmt.Errorf("unmarshal raw values: %w", err)
	}

	otherNames := make([]*OtherName, 0, len(values))

	for _, value := range values {
		if value.Tag != 0 {
			continue
		}

		otherName := &OtherName{}

		value.Bytes, err = asn1.Unmarshal(value.Bytes, &otherName.ID)
		if err != nil {
			return nil, fmt.Errorf("unmarshal ID: %w", err)
		}

		value.Bytes, err = asn1.UnmarshalWithParams(value.Bytes, &otherName.Value, "utf8")
		if err != nil {
			return nil, fmt.Errorf("unmarshal raw name: %w", err)
		}

		if len(value.Bytes) != 0 {
			return nil, fmt.Errorf("othername: entry contains trailing bytes")
		}

		otherNames = append(otherNames, otherName)
	}

	return otherNames, nil
}

// UPNsFromOtherNames returns all UPNsFromOtherNames that are stored in
// certificates otherName extension.
func UPNsFromOtherNames(cert *x509.Certificate) (upns []string, err error) {
	otherNames, err := OtherNames(cert)
	if err != nil {
		return nil, err
	}

	for _, otherName := range otherNames {
		if !otherName.ID.Equal(UPNOID) {
			continue
		}

		var upn string

		_, err = asn1.UnmarshalWithParams(otherName.Value.Bytes, &upn, "utf8")
		if err != nil {
			return nil, fmt.Errorf("unmarshal name: %w", err)
		}

		upns = append(upns, upn)
	}

	return upns, nil
}

// UserAndDomainFromOtherNames returns the user and domain from the first valid
// UPN in the certificate's otherName extension.
func UserAndDomainFromOtherNames(cert *x509.Certificate) (user string, domain string, err error) {
	upns, err := UPNsFromOtherNames(cert)
	if err != nil {
		return "", "", err
	}

	for _, upn := range upns {
		parts := strings.Split(upn, "@")
		if len(parts) == 2 {
			return parts[0], parts[1], nil
		}
	}

	return "", "", fmt.Errorf("found no suitable UPN in certificate")
}
