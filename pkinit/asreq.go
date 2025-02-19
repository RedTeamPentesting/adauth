package pkinit

import (
	cryptRand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	mathRand "math/rand"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// NewASReq generates an ASReq configured for PKINIT.
func NewASReq(
	username string, domain string, cert *x509.Certificate, key *rsa.PrivateKey, dhKey *big.Int, config *config.Config,
) (asReq messages.ASReq, dhClientNonce []byte, err error) {
	asReq, err = messages.NewASReqForTGT(domain, config, types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, username))
	if err != nil {
		return asReq, nil, fmt.Errorf("build generic asreq: %w", err)
	}

	dhClientNonce = NewDiffieHellmanNonce()

	return asReq, dhClientNonce, ConfigureASReq(&asReq, cert, key, dhKey, dhClientNonce)
}

// ConfigureASReq configures an ASReq for PKINIT.
func ConfigureASReq(
	asReq *messages.ASReq, cert *x509.Certificate, key *rsa.PrivateKey, dhKey *big.Int, dhClientNonce []byte,
) error {
	pkAuthenticatorChecksum, err := calculatePKAuthenticatorChecksum(asReq.ReqBody)
	if err != nil {
		return fmt.Errorf("calculate checksum: %w", err)
	}

	publicKey := DiffieHellmanPublicKey(dhKey)

	publicKeyBytes, err := asn1.MarshalWithParams(publicKey, "int")
	if err != nil {
		return err
	}

	now := time.Now().UTC()

	authPack := AuthPack{
		PKAuthenticator: PKAuthenticator{
			CUSec:    int(now.UnixMicro() - now.Truncate(time.Millisecond).UnixMicro()),
			CTime:    now,
			Nonce:    mathRand.Intn(4294967295), //nolint:gosec
			Checksum: pkAuthenticatorChecksum,
		},
		ClientPublicValue: SubjectPublicKeyInfo{
			Algorithm: AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1},
				Parameters: DomainParameters{
					P: DiffieHellmanPrime,
					G: 2,
					Q: 0,
				},
			},
			PublicKey: asn1.BitString{
				Bytes:     publicKeyBytes,
				BitLength: len(publicKeyBytes) * 8,
			},
		},
		SupportedCMSTypes: nil,
		ClientDHNonce:     dhClientNonce,
	}

	authPackBytes, err := asn1.Marshal(authPack)
	if err != nil {
		return fmt.Errorf("marshal auth pack: %w", err)
	}

	signedAuthPack, err := PKCS7Sign(authPackBytes, key, cert)
	if err != nil {
		return fmt.Errorf("create signed authpack: %w", err)
	}

	pkASReq := struct {
		SignedAuthPack     []byte              `asn1:"tag:0"`
		TrustedIdentifiers types.PrincipalName `asn1:"tag:1,explicit,optional"`
		KDCPKID            []byte              `asn1:"tag:2,optional"`
	}{
		SignedAuthPack: signedAuthPack,
	}

	pkASReqBytes, err := asn1.Marshal(pkASReq)
	if err != nil {
		return fmt.Errorf("marshal ASReq: %w", err)
	}

	const paDataTypePKASReq = 16

	asReq.PAData = append(asReq.PAData, types.PAData{
		PADataType:  paDataTypePKASReq,
		PADataValue: pkASReqBytes,
	})

	return nil
}

// NewDiffieHellmanNonce generates a nonce for the Diffie Hellman key exchange.
func NewDiffieHellmanNonce() []byte {
	return randomBytes(32)
}

func calculatePKAuthenticatorChecksum(asReqBody messages.KDCReqBody) ([]byte, error) {
	bodyBytes, err := asReqBody.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal ASReq body: %w", err)
	}

	hash := sha1.Sum(bodyBytes)

	return hash[:], nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)

	_, err := cryptRand.Read(b)
	if err != nil {
		panic(err.Error())
	}

	return b
}
