package pkinit

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestASN1Marshal(t *testing.T) {
	// just a simple asn1.Marshal test that ensures that the asn1 structs do not
	// contain unexpected types (like uint32 instead of int) that only cause
	// errors at runtime.
	tests := []any{
		SignerInfo{
			Version: 1,
			IssuerAndSerialNumber: IssuerAndSerial{
				IssuerName:   asn1.RawValue{},
				SerialNumber: big.NewInt(12345),
			},
			DigestAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5},
				Parameters: asn1.RawValue{Tag: 5},
			},
			DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
				Parameters: asn1.RawValue{Tag: 5},
			},
			EncryptedDigest: []byte("signature"),
		},
		Attribute{
			Type:  asn1.ObjectIdentifier{1, 2, 3},
			Value: asn1.RawValue{},
		},
		IssuerAndSerial{
			IssuerName:   asn1.RawValue{Tag: 16 /* SEQUENCE */},
			SerialNumber: big.NewInt(67890),
		},
		ContentInfo{
			ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		},
		SignedData{
			Version: 1,
			ContentInfo: ContentInfo{
				ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
			},
			SignerInfos: []SignerInfo{},
		},
		RawCertificates{
			Raw: []byte{0x30, 0x03, 0x01, 0x00, 0x00},
		},
		AuthPack{
			PKAuthenticator: PKAuthenticator{
				CUSec:    123,
				CTime:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
				Nonce:    42,
				Checksum: []byte("checksum"),
			},
		},
		PKAuthenticator{
			CUSec:    123,
			CTime:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			Nonce:    42,
			Checksum: []byte("checksum"),
		},
		SubjectPublicKeyInfo{
			Algorithm: AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1},
			},
			PublicKey: asn1.BitString{Bytes: []byte{0x04}, BitLength: 8},
		},
		AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
		},
		DomainParameters{
			P: big.NewInt(23),
			G: 5,
			Q: 11,
		},
		PAPKASRep{
			DHInfo: asn1.RawValue{},
		},
		PAPACRequest{
			IncludePAC: true,
		},
		DHRepInfo{
			DHSignedData:  []byte("data"),
			ServerDHNonce: []byte("nonce"),
		},
		KDCDHKeyInfo{
			SubjectPublicKey: asn1.BitString{Bytes: []byte{0x04}, BitLength: 8},
			Nonce:            big.NewInt(999),
			DHKeyExpication:  time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		},
	}

	for _, val := range tests {
		t.Run(fmt.Sprintf("%T", val), func(t *testing.T) {
			_, err := asn1.MarshalWithParams(val, "")
			if err != nil {
				t.Errorf("asn1.Marshal() failed for %T: %v", val, err)
			}
		})
	}
}
