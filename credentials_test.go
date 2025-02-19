package adauth_test

import (
	"context"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/RedTeamPentesting/adauth"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestKeytab(t *testing.T) {
	expectedNTHash := hex.EncodeToString(make([]byte, 16))
	expectedAES256Key := hex.EncodeToString(make([]byte, 32))
	expectedAES128Key := hex.EncodeToString(make([]byte, 16))
	principal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, testUser)

	testCases := []struct {
		Cred                adauth.Credential
		ShouldHaveRC4Key    bool
		ShouldHaveAES128Key bool
		ShouldHaveAES256Key bool
	}{
		{
			Cred:                adauth.Credential{},
			ShouldHaveRC4Key:    false,
			ShouldHaveAES128Key: false,
			ShouldHaveAES256Key: false,
		},
		{
			Cred: adauth.Credential{
				NTHash: expectedNTHash,
			},
			ShouldHaveRC4Key:    true,
			ShouldHaveAES128Key: false,
			ShouldHaveAES256Key: false,
		},
		{
			Cred: adauth.Credential{
				NTHash: expectedNTHash,
				AESKey: expectedAES128Key,
			},
			ShouldHaveRC4Key:    true,
			ShouldHaveAES128Key: true,
			ShouldHaveAES256Key: false,
		},
		{
			Cred: adauth.Credential{
				NTHash: expectedNTHash,
				AESKey: expectedAES256Key,
			},
			ShouldHaveRC4Key:    true,
			ShouldHaveAES128Key: false,
			ShouldHaveAES256Key: true,
		},
		{
			Cred: adauth.Credential{
				AESKey: expectedAES128Key,
			},
			ShouldHaveRC4Key:    false,
			ShouldHaveAES128Key: true,
			ShouldHaveAES256Key: false,
		},
		{
			Cred: adauth.Credential{
				AESKey: expectedAES256Key,
			},
			ShouldHaveRC4Key:    false,
			ShouldHaveAES128Key: false,
			ShouldHaveAES256Key: true,
		},
	}

	for i, testCase := range testCases {
		testCase := testCase

		t.Run(strconv.Itoa(i), func(t *testing.T) {
			testCase.Cred.Username = testUser
			testCase.Cred.Domain = testDomain

			keyTab, err := testCase.Cred.Keytab()
			if err != nil {
				t.Fatalf("create keytab: %v", err)
			}

			rc4Key, _, rc4Err := keyTab.GetEncryptionKey(principal, strings.ToUpper(testDomain), 0, etypeID.RC4_HMAC)

			switch {
			case testCase.ShouldHaveRC4Key && rc4Err != nil:
				t.Errorf("expected RC4 key but got error: %v", rc4Err)
			case testCase.ShouldHaveRC4Key && len(rc4Key.KeyValue) != 16:
				t.Errorf("RC4 key has %d bytes instead of %d", len(rc4Key.KeyValue), 16)
			case testCase.ShouldHaveRC4Key && rc4Key.KeyType != etypeID.RC4_HMAC:
				t.Errorf("RC4 key type is %d instead of %d", rc4Key.KeyType, etypeID.RC4_HMAC)
			case !testCase.ShouldHaveRC4Key && (rc4Err == nil || len(rc4Key.KeyValue) > 0):
				t.Errorf("RC4 key should not exist")
			}

			aes128Key, _, aes128Err := keyTab.GetEncryptionKey(
				principal, strings.ToUpper(testDomain), 0, etypeID.AES128_CTS_HMAC_SHA1_96)

			switch {
			case testCase.ShouldHaveAES128Key && aes128Err != nil:
				t.Errorf("expected AES128 key but got error: %v:\n%#v\n", aes128Err, keyTab.Entries)
			case testCase.ShouldHaveAES128Key && len(aes128Key.KeyValue) != 16:
				t.Errorf("AES128 key has %d bytes instead of %d", len(aes128Key.KeyValue), 16)
			case testCase.ShouldHaveAES128Key && aes128Key.KeyType != etypeID.AES128_CTS_HMAC_SHA1_96:
				t.Errorf("AES128 key type is %d instead of %d", aes128Key.KeyType, etypeID.AES128_CTS_HMAC_SHA1_96)
			case !testCase.ShouldHaveAES128Key && (aes128Err == nil || len(aes128Key.KeyValue) > 0):
				t.Errorf("AES128 key should not exist")
			}

			aes256Key, _, aes256Err := keyTab.GetEncryptionKey(
				principal, strings.ToUpper(testDomain), 0, etypeID.AES256_CTS_HMAC_SHA1_96)

			switch {
			case testCase.ShouldHaveAES256Key && aes256Err != nil:
				t.Errorf("expected AES256 key but got error: %v", aes256Err)
			case testCase.ShouldHaveAES256Key && len(aes256Key.KeyValue) != 32:
				t.Errorf("AES256 key has %d bytes instead of %d", len(aes256Key.KeyValue), 32)
			case testCase.ShouldHaveAES256Key && aes256Key.KeyType != etypeID.AES256_CTS_HMAC_SHA1_96:
				t.Errorf("AES256 key type is %d instead of %d", aes256Key.KeyType, etypeID.AES256_CTS_HMAC_SHA1_96)
			case !testCase.ShouldHaveAES256Key && (aes256Err == nil || len(aes256Key.KeyValue) > 0):
				t.Errorf("AES256 key should not exist")
			}
		})
	}
}

func TestSetDC(t *testing.T) {
	creds := adauth.Credential{
		Username: testUser,
		Domain:   testDomain,
		Resolver: &testResolver{},
	}

	_, err := creds.DC(context.Background(), "host")
	if err == nil {
		t.Fatalf("expected creds.DC() to fail initially")
	}

	dcHostname := "dc." + testDomain
	creds.SetDC(dcHostname)

	dc, err := creds.DC(context.Background(), "host")
	if err != nil {
		t.Fatalf("get DC: %v", err)
	}

	if dc.Address() != dcHostname {
		t.Fatalf("DC address is %q instead of %q", dc.Address(), dcHostname)
	}
}

func TestLookupDC(t *testing.T) {
	dcHostname := "dc." + testDomain

	creds := adauth.Credential{
		Username: testUser,
		Domain:   testDomain,
		Resolver: &testResolver{
			SRV: map[string]map[string]map[string]struct {
				Name string
				SRV  []*net.SRV
			}{
				"kerberos": {
					"tcp": {
						testDomain: {
							Name: dcHostname,
							SRV: []*net.SRV{
								{Target: dcHostname, Port: 88},
							},
						},
					},
				},
			},
		},
	}

	dc, err := creds.DC(context.Background(), "host")
	if err != nil {
		t.Fatalf("get DC: %v", err)
	}

	if dc.AddressWithoutPort() != dcHostname {
		t.Fatalf("DC address is %q instead of %q", dc.Address(), dcHostname)
	}
}
