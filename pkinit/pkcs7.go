package pkinit

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// PKCS7Sign signs the data according to PKCS#7.
func PKCS7Sign(data []byte, key *rsa.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	serializedData, err := asn1.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal data: %w", err)
	}

	rawCert, err := RawCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("marshal certificate: %w", err)
	}

	digest := sha1.Sum(data)

	serializedDigest, err := asn1.Marshal(digest[:])
	if err != nil {
		return nil, fmt.Errorf("marshal digest: %w", err)
	}

	serializedPKInitOID, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1})
	if err != nil {
		return nil, fmt.Errorf("marshal PKInit OID: %w", err)
	}

	sha1AlgorithmIdentifier := pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26},
	}

	rsaWithSHA1AlgorithmIdentifier := pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5},
	}

	authenticatedAttributes := []Attribute{
		{
			// ContentType
			Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3},
			// id-pkinit-authData
			Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: serializedPKInitOID},
		},
		{
			// MessageDigest
			Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4},
			Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: serializedDigest},
		},
	}

	signature, err := signAuthenicatedAttributes(authenticatedAttributes, key)
	if err != nil {
		return nil, fmt.Errorf("sign authenticated data: %w", err)
	}

	signedDataBytes, err := asn1.Marshal(SignedData{
		Version:                    3,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{sha1AlgorithmIdentifier},
		ContentInfo: ContentInfo{
			// id-pkinit-authData
			ContentType: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1},
			Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: serializedData, IsCompound: true},
		},
		Certificates: rawCert,
		SignerInfos: []SignerInfo{
			{
				Version: 1,
				IssuerAndSerialNumber: IssuerAndSerial{
					IssuerName:   asn1.RawValue{FullBytes: cert.RawIssuer},
					SerialNumber: cert.SerialNumber,
				},
				DigestAlgorithm:           sha1AlgorithmIdentifier,
				AuthenticatedAttributes:   authenticatedAttributes,
				DigestEncryptionAlgorithm: rsaWithSHA1AlgorithmIdentifier,
				EncryptedDigest:           signature,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal signed data: %w", err)
	}

	contentInfo := ContentInfo{
		// signed data
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: signedDataBytes, IsCompound: true},
	}

	signedContent, err := asn1.Marshal(contentInfo)
	if err != nil {
		return nil, fmt.Errorf("marshal signed content: %w", err)
	}

	return signedContent, nil
}

func signAuthenicatedAttributes(attrs []Attribute, key *rsa.PrivateKey) ([]byte, error) {
	rawAuthenticatedAttributesAsSequence, err := asn1.Marshal(struct {
		A []Attribute `asn1:"set"`
	}{A: attrs})
	if err != nil {
		return nil, fmt.Errorf("marshal authenticated data: %w", err)
	}

	// Remove the leading sequence octets
	var rawAuthenticatedAttributes asn1.RawValue

	_, err = asn1.Unmarshal(rawAuthenticatedAttributesAsSequence, &rawAuthenticatedAttributes)
	if err != nil {
		return nil, fmt.Errorf("remove sequence bytes: %w", err)
	}

	hash := sha1.Sum(rawAuthenticatedAttributes.Bytes)

	return rsa.SignPKCS1v15(nil, key, crypto.SHA1, hash[:])
}
