package pkinit

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/jcmturner/gokrb5/v8/types"
)

var (
	signedDataOID                                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	idPKINITAuthDataOID                                  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}
	idPKINITDHKeyDataOID                                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 2}
	sha1HashOID                                          = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	sha1WithRSAEncryptionOID                             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	contentTypeOID                                       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	ephemeralStaticDiffieHellmanKeyAgreementAlgorithmOID = asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}
	messageDigestOID                                     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

type SignerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     IssuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []Attribute `asn1:"optional,omitempty,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []pkix.AttributeTypeAndValue `asn1:"optional,omitempty,tag:1"`
}

type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type IssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type SignedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                ContentInfo
	Certificates               RawCertificates       `asn1:"optional,tag:0"`
	CRLs                       []x509.RevocationList `asn1:"optional,tag:1"`
	SignerInfos                []SignerInfo          `asn1:"set"`
}

type RawCertificates struct {
	Raw asn1.RawContent
}

func RawCertificate(cert *x509.Certificate) (RawCertificates, error) {
	val := asn1.RawValue{Bytes: cert.Raw, Class: 2, Tag: 0, IsCompound: true}

	b, err := asn1.Marshal(val)
	if err != nil {
		return RawCertificates{}, err
	}

	return RawCertificates{Raw: b}, nil
}

type AuthPack struct {
	// AuthPack ::= SEQUENCE {
	// 	pkAuthenticator         [0] PKAuthenticator,
	// 	clientPublicValue       [1] SubjectPublicKeyInfo OPTIONAL,
	// 	supportedCMSTypes       [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
	// 	clientDHNonce           [3] DHNonce OPTIONAL,
	// 	...,
	// 	supportedKDFs		[4] SEQUENCE OF KDFAlgorithmId OPTIONAL,
	// 	...
	// }
	PKAuthenticator   PKAuthenticator            `asn1:"tag:0,explicit"`
	ClientPublicValue SubjectPublicKeyInfo       `asn1:"tag:1,explicit,optional"`
	SupportedCMSTypes []pkix.AlgorithmIdentifier `asn1:"tag:2,explicit,optional"`
	ClientDHNonce     []byte                     `asn1:"tag:3,explicit,optional"`
}

type PKAuthenticator struct {
	// PKAuthenticator ::= SEQUENCE {
	// 	cusec                   [0] INTEGER -- (0..999999) --,
	// 	ctime                   [1] KerberosTime,
	// 	nonce                   [2] INTEGER (0..4294967295),
	// 	paChecksum              [3] OCTET STRING OPTIONAL,
	// 	...
	// asn1
	CUSec    int       `asn1:"tag:0,explicit"`
	CTime    time.Time `asn1:"tag:1,explicit,generalized"`
	Nonce    int       `asn1:"tag:2,explicit"`
	Checksum []byte    `asn1:"tag:3,explicit,optional"`
}

type SubjectPublicKeyInfo struct {
	// SubjectPublicKeyInfo  ::=  SEQUENCE  {
	// 	algorithm            AlgorithmIdentifier{PUBLIC-KEY,
	// 							{PublicKeyAlgorithms}},
	// 	subjectPublicKey     BIT STRING  }
	Algorithm AlgorithmIdentifier
	PublicKey asn1.BitString
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier `asn1:"implicit"`
	Parameters DomainParameters      `asn1:"implicit,optional"`
}

type DomainParameters struct {
	// DomainParameters ::= SEQUENCE {
	// 	p       INTEGER, -- odd prime, p=jq +1
	// 	g       INTEGER, -- generator, g
	// 	q       INTEGER, -- factor of p-1
	// 	j       INTEGER OPTIONAL, -- subgroup factor
	// 	validationParams  ValidationParams OPTIONAL }
	P *big.Int
	G int
	Q int
}

type PAPKASRep struct {
	DHInfo asn1.RawValue
}

type PAPACRequest struct {
	IncludePAC bool `asn1:"explicit,tag:0"`
}

func (p *PAPACRequest) AsPAData() types.PAData {
	// make sure we marshal the struct and not the pointer to the struct which
	// would cause an error and also make sure we don't panic when receiver is
	// nil.
	pacRequest := PAPACRequest{}
	if p != nil {
		pacRequest.IncludePAC = p.IncludePAC
	}

	pacRequestBytes, err := asn1.Marshal(pacRequest)
	if err != nil {
		panic(fmt.Sprintf("unexpected error marshalling PAPACRequest: %v", err))
	}

	const paDataTypePACRequest = 128

	return types.PAData{
		PADataType:  paDataTypePACRequest,
		PADataValue: pacRequestBytes,
	}
}

type DHRepInfo struct {
	DHSignedData  []byte `asn1:"tag:0"`
	ServerDHNonce []byte `asn1:"tag:1,explicit,optional"`
}

type KDCDHKeyInfo struct {
	SubjectPublicKey asn1.BitString `asn1:"tag:0,explicit"`
	Nonce            *big.Int       `asn1:"tag:1,explicit"`
	DHKeyExpication  time.Time      `asn1:"tag:2,explicit,optional,generalized"`
}

type AuthoirzationDataElement struct {
	ADType int    `asn1:"tag:0"`
	ADData []byte `asn1:"tag:1"`
}

type AuthoirzationData []AuthoirzationDataElement
