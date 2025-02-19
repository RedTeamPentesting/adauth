package othername_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/RedTeamPentesting/adauth/othername"
)

func TestOtherName(t *testing.T) {
	t.Parallel()

	names := []string{"a", "b", "c"}

	ext, err := othername.ExtensionFromUPNs(names...)
	if err != nil {
		t.Fatalf("generate otherName extension: %v", err)
	}

	cert := &x509.Certificate{
		ExtraExtensions: []pkix.Extension{ext},
	}

	parsedNames, err := othername.UPNs(cert)
	if err != nil {
		t.Fatalf("parse otherNames: %v", err)
	}

	if len(names) != len(parsedNames) {
		t.Fatalf("got %d (%#v) names instead of %d (%#v)",
			len(parsedNames), parsedNames, len(names), names)
	}

	for i := 0; i < len(names); i++ {
		if names[i] != parsedNames[i] {
			t.Errorf("got %q instead of %q", parsedNames[i], names[i])
		}
	}
}
