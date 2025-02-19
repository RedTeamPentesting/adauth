package pkinit

import (
	"crypto/sha1"
	"encoding/asn1"
	"fmt"
	"math/big"

	krb5crypto "github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Decrypt decrypts the encrypted parts of an ASRep with the key derived during PKINIT.
func Decrypt(asRep *messages.ASRep, dhKey *big.Int, dhClientNonce []byte) (pkinitKey types.EncryptionKey, err error) {
	ekey, err := ExtractNegotiatedKey(asRep, dhKey, dhClientNonce)
	if err != nil {
		return pkinitKey, fmt.Errorf("extract negotiated key: %w", err)
	}

	decrypted, err := krb5crypto.DecryptEncPart(asRep.EncPart, ekey, keyusage.AS_REP_ENCPART)
	if err != nil {
		return pkinitKey, fmt.Errorf("decrypt: %w", err)
	}

	err = asRep.DecryptedEncPart.Unmarshal(decrypted)
	if err != nil {
		return pkinitKey, fmt.Errorf("unmarshal encrypted part: %w", err)
	}

	return ekey, nil
}

// ExtractNegotiatedKey extracts the key derived during PKINIT.
func ExtractNegotiatedKey(
	asRep *messages.ASRep, dhKey *big.Int, dhClientNonce []byte,
) (ekey types.EncryptionKey, err error) {
	var paPKASRepBytes []byte

	for _, paData := range asRep.PAData {
		if paData.PADataType == 17 {
			paPKASRepBytes = paData.PADataValue
		}
	}

	if paPKASRepBytes == nil {
		return ekey, fmt.Errorf("could not find pA-PK-AS-REP structure")
	}

	var paPKASRep DHRepInfo

	err = unmarshalFromRawValue(paPKASRepBytes, &paPKASRep)
	if err != nil {
		return ekey, fmt.Errorf("unmarshal  PA-PK-AS-Rep: %w", err)
	}

	var contentInfo ContentInfo

	_, err = asn1.Unmarshal(paPKASRep.DHSignedData, &contentInfo)
	if err != nil {
		return ekey, fmt.Errorf("unmarshal signed data: %w", err)
	}

	if !contentInfo.ContentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		return ekey, fmt.Errorf("unexpected outer content type: %s", contentInfo.ContentType)
	}

	var signedData SignedData

	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		return ekey, fmt.Errorf("unmarshal signed data: %w", err)
	}

	if !signedData.ContentInfo.ContentType.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 2}) {
		return ekey, fmt.Errorf("unexpected inner content type: %s", signedData.ContentInfo.ContentType)
	}

	var keyInfo KDCDHKeyInfo

	err = unmarshalFromRawValue(signedData.ContentInfo.Content.Bytes, &keyInfo)
	if err != nil {
		return ekey, fmt.Errorf("unmarshal key info: %w", err)
	}

	if len(keyInfo.SubjectPublicKey.Bytes) < 7 {
		return ekey, fmt.Errorf("public key is too short")
	}

	pubkeyData, err := asn1.Marshal(keyInfo.SubjectPublicKey)
	if err != nil {
		return ekey, fmt.Errorf("marshal public key: %w", err)
	}

	pubKey := big.NewInt(0)
	pubKey.SetBytes(pubkeyData[7:])

	sharedSecret := DiffieHellmanSharedSecret(dhKey, pubKey)
	sharedKey := sharedSecret.Bytes()
	sharedKey = append(sharedKey, dhClientNonce...)
	sharedKey = append(sharedKey, paPKASRep.ServerDHNonce...)

	var keyType int32

	switch asRep.EncPart.EType {
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		keyType = etypeID.AES256_CTS_HMAC_SHA1_96
		sharedKey = truncateKey(sharedKey, 32)
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		keyType = etypeID.AES128_CTS_HMAC_SHA1_96
		sharedKey = truncateKey(sharedKey, 16)
	default:
		return ekey, fmt.Errorf("PKInit is not implemented for EType %d", asRep.EncPart.EType)
	}

	return types.EncryptionKey{
		KeyType:  keyType,
		KeyValue: sharedKey,
	}, nil
}

func unmarshalFromRawValue(data []byte, v any) error {
	var raw asn1.RawValue

	rest, err := asn1.Unmarshal(data, &raw)
	if err != nil {
		return fmt.Errorf("unmarshal raw: %w", err)
	}

	if len(rest) != 0 {
		return fmt.Errorf("remaining data found after unmarshalling raw value")
	}

	rest, err = asn1.Unmarshal(raw.Bytes, v)
	if err != nil {
		return err
	}

	if len(rest) != 0 {
		return fmt.Errorf("remaining data found after unmarshalling")
	}

	return nil
}

func truncateKey(key []byte, size int) []byte {
	var output []byte

	idx := byte(0)

	for len(output) < size {
		digest := sha1.Sum(append([]byte{idx}, key...))
		if len(output)+len(digest) > size {
			output = append(output, digest[:size-len(output)]...)

			break
		}

		output = append(output, digest[:]...)

		idx++
	}

	return output
}
