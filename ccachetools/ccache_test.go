package ccachetools_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RedTeamPentesting/adauth/ccachetools"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

var (
	testASRep = messages.ASRep{
		KDCRepFields: messages.KDCRepFields{
			PVNO:    5,
			MsgType: 11,
			CRealm:  "realm",
			CName:   types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"),
			Ticket: messages.Ticket{
				TktVNO: 5,
				Realm:  "realm",
				SName:  types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "krbtgt/redteam"),
				DecryptedEncPart: messages.EncTicketPart{
					Key:       types.EncryptionKey{},
					CName:     types.NewPrincipalName(0, ""),
					StartTime: time.Now(),
					AuthTime:  time.Now(),
					EndTime:   time.Now(),
					RenewTill: time.Now(),
				},
			},
			EncPart: types.EncryptedData{
				EType:  18,
				KVNO:   2,
				Cipher: []byte{1, 2, 3},
			},
			DecryptedEncPart: messages.EncKDCRepPart{
				Key: types.EncryptionKey{
					KeyType:  18,
					KeyValue: []byte{1, 3, 3, 7},
				},
				SRealm:    "realm",
				SName:     types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "krbtgt/redteam"),
				StartTime: time.Now(),
				AuthTime:  time.Now(),
				EndTime:   time.Now(),
				RenewTill: time.Now(),
			},
		},
	}
	testTGSRep = messages.TGSRep(testASRep)
)

func TestNewCCacheFromASRep(t *testing.T) {
	t.Parallel()

	ccache, err := ccachetools.NewCCacheFromASRep(testASRep)
	if err != nil {
		t.Fatalf("NewCCacheFromASRep: %v", err)
	}

	validateCCache(t, ccache)
}

func TestNewCCacheFromTGSRep(t *testing.T) {
	t.Parallel()

	ccache, err := ccachetools.NewCCacheFromTGSRep(testTGSRep)
	if err != nil {
		t.Fatalf("NewCCacheFromTGSRep: %v", err)
	}

	validateCCache(t, ccache)
}

func TestNewCCache(t *testing.T) {
	t.Parallel()

	ccache, err := ccachetools.NewCCache(
		testASRep.Ticket, testASRep.DecryptedEncPart.Key,
		testASRep.DecryptedEncPart.SName, testASRep.CName, testASRep.CRealm,
		testASRep.DecryptedEncPart.AuthTime, testASRep.DecryptedEncPart.StartTime,
		testASRep.DecryptedEncPart.EndTime, testASRep.DecryptedEncPart.RenewTill)
	if err != nil {
		t.Fatalf("NewCCacheFromTGSRep: %v", err)
	}

	validateCCache(t, ccache)
}

func TestMarshalCCache(t *testing.T) {
	t.Parallel()

	ccache, err := ccachetools.NewCCacheFromASRep(testASRep)
	if err != nil {
		t.Fatalf("new CCache: %v", err)
	}

	ccacheBytes, err := ccachetools.MarshalCCache(ccache)
	if err != nil {
		t.Fatalf("marshal CCache: %v", err)
	}

	var parsedCCache credentials.CCache

	err = parsedCCache.Unmarshal(ccacheBytes)
	if err != nil {
		t.Fatalf("unmarshal CCache: %v", err)
	}

	validateCCache(t, &parsedCCache)
}

func TestUnencryptedASRep(t *testing.T) {
	t.Parallel()

	_, err := ccachetools.NewCCacheFromASRep(messages.ASRep{
		KDCRepFields: messages.KDCRepFields{
			PVNO:    5,
			MsgType: 11,
			CRealm:  "realm",
			CName:   types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"),
			Ticket: messages.Ticket{
				TktVNO: 5,
				Realm:  "realm",
				SName:  types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "krbtgt/redteam"),
				DecryptedEncPart: messages.EncTicketPart{
					Key:       types.EncryptionKey{},
					CName:     types.NewPrincipalName(0, ""),
					StartTime: time.Now(),
					AuthTime:  time.Now(),
					EndTime:   time.Now(),
					RenewTill: time.Now(),
				},
			},
			EncPart: types.EncryptedData{
				EType:  18,
				KVNO:   2,
				Cipher: []byte{1, 2, 3},
			},
		},
	})
	if err == nil {
		t.Fatalf("NewCCache did not fail for undecrypted CCache")
	}
}

func TestUnencryptedTGSRep(t *testing.T) {
	t.Parallel()

	_, err := ccachetools.NewCCacheFromTGSRep(messages.TGSRep{
		KDCRepFields: messages.KDCRepFields{
			PVNO:    5,
			MsgType: 11,
			CRealm:  "realm",
			CName:   types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"),
			Ticket: messages.Ticket{
				TktVNO: 5,
				Realm:  "realm",
				SName:  types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "krbtgt/redteam"),
				DecryptedEncPart: messages.EncTicketPart{
					Key:       types.EncryptionKey{},
					CName:     types.NewPrincipalName(0, ""),
					StartTime: time.Now(),
					AuthTime:  time.Now(),
					EndTime:   time.Now(),
					RenewTill: time.Now(),
				},
			},
			EncPart: types.EncryptedData{
				EType:  18,
				KVNO:   2,
				Cipher: []byte{1, 2, 3},
			},
		},
	})
	if err == nil {
		t.Fatalf("NewCCache did not fail for undecrypted CCache")
	}
}

func validateCCache(t *testing.T, ccache *credentials.CCache) {
	t.Helper()

	if ccache.DefaultPrincipal.Realm != strings.ToUpper(testASRep.CRealm) {
		t.Errorf("default principal realm %q does not match %q",
			ccache.DefaultPrincipal.Realm, strings.ToUpper(testASRep.CRealm))
	}

	if ccache.DefaultPrincipal.PrincipalName.NameType != testASRep.CName.NameType {
		t.Errorf("default principal name type %d does not match %d",
			ccache.DefaultPrincipal.PrincipalName.NameType, testASRep.CName.NameType)
	}

	if !slices.Equal(ccache.DefaultPrincipal.PrincipalName.NameString, testASRep.CName.NameString) {
		t.Errorf("default principal name string %v does not match %v",
			ccache.DefaultPrincipal.PrincipalName.NameString, testASRep.CName.NameString)
	}

	if len(ccache.Credentials) != 1 {
		t.Fatalf("found %d credentials instead of 1", len(ccache.Credentials))
	}

	cred := ccache.Credentials[0]

	if cred.Key.KeyType != testASRep.DecryptedEncPart.Key.KeyType {
		t.Errorf("key type %d does not match %d",
			cred.Key.KeyType, testASRep.DecryptedEncPart.Key.KeyType)
	}

	if !bytes.Equal(cred.Key.KeyValue, testASRep.DecryptedEncPart.Key.KeyValue) {
		t.Errorf("key value does not match")
	}

	if cred.Ticket == nil {
		t.Errorf("ticket is empty")
	}

	if cred.Client.Realm != testASRep.CRealm {
		t.Errorf("client realm %q does not match %s", cred.Client.Realm, testASRep.CRealm)
	}

	if cred.Client.PrincipalName.NameType != testASRep.CName.NameType {
		t.Errorf("client name type %d does not match %d",
			cred.Client.PrincipalName.NameType, testASRep.CName.NameType)
	}

	if !slices.Equal(cred.Client.PrincipalName.NameString, testASRep.CName.NameString) {
		t.Errorf("client name string %v does not match %v",
			cred.Client.PrincipalName.NameString, testASRep.CName.NameString)
	}

	if cred.Server.Realm != testASRep.CRealm {
		t.Errorf("server realm %q does not match %s", cred.Server.Realm, testASRep.CRealm)
	}

	if cred.Server.PrincipalName.NameType != testASRep.CName.NameType {
		t.Errorf("server name type %d does not match %d",
			cred.Server.PrincipalName.NameType, testASRep.DecryptedEncPart.SName.NameType)
	}

	if !slices.Equal(cred.Server.PrincipalName.NameString, testASRep.DecryptedEncPart.SName.NameString) {
		t.Errorf("server name string %v does not match %v",
			cred.Server.PrincipalName.NameString, testASRep.DecryptedEncPart.SName.NameString)
	}

	if cred.AuthTime.Unix() != testASRep.DecryptedEncPart.AuthTime.Unix() {
		t.Errorf("auth time %s does not match %s",
			cred.AuthTime, testASRep.DecryptedEncPart.AuthTime)
	}

	if cred.StartTime.Unix() != testASRep.DecryptedEncPart.StartTime.Unix() {
		t.Errorf("start time %s does not match %s",
			cred.StartTime, testASRep.DecryptedEncPart.StartTime)
	}

	if cred.EndTime.Unix() != testASRep.DecryptedEncPart.EndTime.Unix() {
		t.Errorf("end time %s does not match %s",
			cred.EndTime, testASRep.DecryptedEncPart.EndTime)
	}

	if cred.RenewTill.Unix() != testASRep.DecryptedEncPart.RenewTill.Unix() {
		t.Errorf("renew time %s does not match %s",
			cred.RenewTill, testASRep.DecryptedEncPart.RenewTill)
	}
}
