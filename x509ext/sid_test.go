package x509ext_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"testing"

	"github.com/RedTeamPentesting/adauth/x509ext"
)

func TestSID(t *testing.T) {
	t.Parallel()

	sid := "S-1-5-32-544"

	ext, err := x509ext.NewNTDSCaSecurityExt(sid)
	if err != nil {
		t.Fatalf("generate SID extension: %v", err)
	}

	cert := &x509.Certificate{
		ExtraExtensions: []pkix.Extension{ext},
	}

	parsedSID, err := x509ext.SID(cert)
	if err != nil {
		t.Fatalf("parse otherNames: %v", err)
	}

	if parsedSID != sid {
		t.Fatalf("parsed SID %s instead of %s", parsedSID, sid)
	}
}

func TestParseSID(t *testing.T) {
	expectedSID := "S-1-5-21-3562467320-83266577-1006951523-1141"

	testExtensionData, err := base64.StdEncoding.DecodeString(
		"MD6gPAYKKwYBBAGCNxkCAaAuBCxTLTEtNS0yMS0zNTYyNDY3MzIwLTgzMjY2NTc3LTEwMDY5NTE1MjMtMTE0MQ==",
	)
	if err != nil {
		t.Fatalf("decode test extension: %v", err)
	}

	sid, err := x509ext.SIDFromExtension(pkix.Extension{
		Id:    x509ext.NTDSCASecurityExtOID,
		Value: testExtensionData,
	})
	if err != nil {
		t.Fatalf("SIDFromExtension: %v", err)
	}

	if sid != expectedSID {
		t.Fatalf("extracted SID is %q instead of %q", sid, expectedSID)
	}
}
