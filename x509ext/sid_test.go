package x509ext_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
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
