package pkinit_test

import (
	"encoding/asn1"
	"math"
	"testing"
	"time"

	"github.com/RedTeamPentesting/adauth/pkinit"
)

func TestPKAuthenticatorNonceAllowsUint32Range(t *testing.T) {
	t.Parallel()

	const maxUint32Nonce int64 = math.MaxUint32

	authenticator := pkinit.PKAuthenticator{
		CUSec: 123456,
		CTime: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
		Nonce: maxUint32Nonce,
	}

	data, err := asn1.Marshal(authenticator)
	if err != nil {
		t.Fatalf("marshal PKAuthenticator: %v", err)
	}

	var decoded pkinit.PKAuthenticator

	_, err = asn1.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("unmarshal PKAuthenticator: %v", err)
	}

	if decoded.Nonce != maxUint32Nonce {
		t.Fatalf("nonce is %d instead of %d", decoded.Nonce, maxUint32Nonce)
	}
}
