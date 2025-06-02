package adauth_test

import (
	"context"
	"net"
	"testing"

	"github.com/RedTeamPentesting/adauth"
)

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

func TestUPN(t *testing.T) {
	t.Run("user and domain", func(t *testing.T) {
		expcetedUPN := "foo@bar"
		upn := (&adauth.Credential{Username: "foo", Domain: "bar"}).UPN()

		if upn != expcetedUPN {
			t.Errorf("UPN is %q insteaf of %q", upn, expcetedUPN)
		}
	})

	t.Run("user without domain", func(t *testing.T) {
		expcetedUPN := "foo"
		upn := (&adauth.Credential{Username: "foo"}).UPN()

		if upn != expcetedUPN {
			t.Errorf("UPN is %q insteaf of %q", upn, expcetedUPN)
		}
	})

	t.Run("domain without username", func(t *testing.T) {
		expcetedUPN := "@bar"
		upn := (&adauth.Credential{Domain: "bar"}).UPN()

		if upn != expcetedUPN {
			t.Errorf("UPN is %q insteaf of %q", upn, expcetedUPN)
		}
	})

	t.Run("no username and no domain", func(t *testing.T) {
		expcetedUPN := ""
		upn := (&adauth.Credential{}).UPN()

		if upn != expcetedUPN {
			t.Errorf("UPN is %q insteaf of %q", upn, expcetedUPN)
		}
	})
}
