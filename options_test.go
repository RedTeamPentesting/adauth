package adauth_test

import (
	"context"
	"encoding/hex"
	"net"
	"strconv"
	"testing"

	"github.com/RedTeamPentesting/adauth"
)

const (
	testUser   = "someuser"
	testDomain = "domain.tld"
)

func TestUsernameAndDomainParsing(t *testing.T) {
	expectedUPN := testUser + "@" + testDomain
	expectedLogonName := testDomain + `\` + testUser
	expectedImpacketLogonName := testDomain + "/" + testUser

	testCases := []struct {
		Name string
		Opts adauth.Options
	}{
		{
			Name: "UPN",
			Opts: adauth.Options{User: testUser + "@" + testDomain},
		},
		{
			Name: "logon-name",
			Opts: adauth.Options{User: testDomain + `\` + testUser},
		},
		{
			Name: "impacket-style",
			Opts: adauth.Options{User: testDomain + `/` + testUser},
		},
		{
			Name: "pfx",
			Opts: adauth.Options{PFXFileName: "testdata/someuser@domain.tld.pfx"},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.Name, func(t *testing.T) {
			creds, err := testCase.Opts.NoTarget()
			if err != nil {
				t.Fatalf("get credentials: %v", err)
			}

			if creds.Username != testUser {
				t.Errorf("username %q is not %q", creds.Username, testUser)
			}

			if creds.Domain != testDomain {
				t.Errorf("domain %q is not %q", creds.Domain, testDomain)
			}

			upn := creds.UPN()
			if upn != expectedUPN {
				t.Errorf("UPN %q is not %q", upn, expectedUPN)
			}

			logonName := creds.LogonName()
			if logonName != expectedLogonName {
				t.Errorf("logon name %q is not %q", logonName, expectedLogonName)
			}

			impacketLogonName := creds.ImpacketLogonName()
			if impacketLogonName != expectedImpacketLogonName {
				t.Errorf("impacket-style logon name %q is not %q", impacketLogonName, expectedImpacketLogonName)
			}
		})
	}
}

func TestDomainFromTargetHostname(t *testing.T) {
	opts := adauth.Options{
		User: testUser,
	}

	creds, _, err := opts.WithTarget(context.Background(), "cifs", "host."+testDomain)
	if err != nil {
		t.Fatalf("get credentials: %v", err)
	}

	if creds.Domain != testDomain {
		t.Errorf("domain is %q instead of %q", creds.Domain, testDomain)
	}

	// ignore domain in hostname for local authentication
	opts = adauth.Options{
		User: "./" + testUser,
	}

	creds, _, err = opts.WithTarget(context.Background(), "cifs", "host."+testDomain)
	if err != nil {
		t.Fatalf("get credentials: %v", err)
	}

	if creds.Domain != "." {
		t.Errorf("domain is %q instead of %q", creds.Domain, ".")
	}
}

func TestDCTarget(t *testing.T) {
	dcHost := "dc." + testDomain
	expectedSPN := "ldap/" + dcHost

	opts := adauth.Options{
		User: testUser + `@` + testDomain,
		Resolver: &testResolver{
			SRV: map[string]map[string]map[string]struct {
				Name string
				SRV  []*net.SRV
			}{
				"ldap": {
					"tcp": {
						testDomain: {
							Name: dcHost,
							SRV: []*net.SRV{
								{Target: dcHost, Port: 389},
							},
						},
					},
				},
			},
		},
	}

	_, dc, err := opts.WithDCTarget(context.Background(), "ldap")
	if err != nil {
		t.Fatalf("get DC target: %v", err)
	}

	if dc.Address() != net.JoinHostPort(dcHost, "389") {
		t.Fatalf("DC address is %q instead of %q", dc.Address(), net.JoinHostPort(dcHost, "389"))
	}

	if dc.AddressWithoutPort() != dcHost {
		t.Fatalf("DC address without port is %q instead of %q", dc.Address(), dcHost)
	}

	if dc.Port != "389" {
		t.Errorf("DC port is %q instead of %q", dc.Port, "389")
	}

	spn, err := dc.SPN(context.Background())
	if err != nil {
		t.Fatalf("get DC SPN: %v", err)
	}

	if spn != expectedSPN {
		t.Errorf("DC SPN is %q instead of %q", spn, expectedSPN)
	}
}

func TestDCTargetWithoutSRVRecord(t *testing.T) {
	dcHost := "dc." + testDomain
	dcIP := net.ParseIP("10.0.0.1")
	expectedSPN := "ldap/" + dcHost

	opts := adauth.Options{
		User: testUser + `@` + testDomain,
		Resolver: &testResolver{
			HostToAddr: map[string][]net.IP{
				testDomain: {dcIP},
			},
			AddrToHost: map[string][]string{
				dcIP.String(): {dcHost},
			},
		},
	}

	_, dc, err := opts.WithDCTarget(context.Background(), "ldap")
	if err != nil {
		t.Fatalf("get DC target: %v", err)
	}

	if dc.Address() != net.JoinHostPort(dcHost, "389") {
		t.Fatalf("DC address is %q instead of %q", dc.Address(), net.JoinHostPort(dcHost, "389"))
	}

	if dc.AddressWithoutPort() != dcHost {
		t.Fatalf("DC address without port is %q instead of %q", dc.Address(), dcHost)
	}

	if dc.Port != "389" {
		t.Errorf("DC port is %q instead of %q", dc.Port, "389")
	}

	spn, err := dc.SPN(context.Background())
	if err != nil {
		t.Fatalf("get DC SPN: %v", err)
	}

	if spn != expectedSPN {
		t.Errorf("DC SPN is %q instead of %q", spn, expectedSPN)
	}
}

func TestDCTargetNoReverseLookup(t *testing.T) {
	dcIP := net.ParseIP("10.0.0.1")

	opts := adauth.Options{
		User: testUser + `@` + testDomain,
		Resolver: &testResolver{
			HostToAddr: map[string][]net.IP{
				testDomain: {dcIP},
			},
		},
	}

	_, dc, err := opts.WithDCTarget(context.Background(), "ldap")
	if err != nil {
		t.Fatalf("get DC target: %v", err)
	}

	if dc.Address() != net.JoinHostPort(dcIP.String(), "389") {
		t.Fatalf("DC address is %q instead of %q", dc.Address(), net.JoinHostPort(dcIP.String(), "389"))
	}
}

func TestKerberos(t *testing.T) {
	upn := testUser + `@` + testDomain

	testCases := []struct {
		Opts              adauth.Options
		ShouldUseKerberos bool
	}{
		{
			Opts: adauth.Options{
				User:     upn,
				Password: "pass",
			},
			ShouldUseKerberos: false,
		},
		{
			Opts: adauth.Options{
				User:   upn,
				AESKey: hex.EncodeToString(make([]byte, 16)),
			},
			ShouldUseKerberos: true,
		},
		{
			Opts: adauth.Options{
				User:     upn,
				Password: "test",
				AESKey:   hex.EncodeToString(make([]byte, 16)),
			},
			ShouldUseKerberos: false,
		},
		{
			Opts: adauth.Options{
				User:          upn,
				Password:      "pass",
				ForceKerberos: true,
			},
			ShouldUseKerberos: true,
		},
		{
			Opts: adauth.Options{
				User:        upn,
				PFXFileName: "testdata/someuser@domain.tld.pfx",
			},
			ShouldUseKerberos: false,
		},
		{
			Opts: adauth.Options{
				User: upn,
				// CCache indicates kerberos usage, but only if file is present
				// (even though it might be empty)
				CCache: "testdata/empty.ccache",
			},
			ShouldUseKerberos: true,
		},
		{
			Opts: adauth.Options{
				User: upn,
				// CCache does not matter if file is not even there
				CCache: "testdata/doesnotexist",
			},
			ShouldUseKerberos: false,
		},
	}

	for i, testCase := range testCases {
		testCase := testCase

		t.Run(strconv.Itoa(i), func(t *testing.T) {
			testCase.Opts.DomainController = "dc.domain.tld"

			_, target, err := testCase.Opts.WithDCTarget(context.Background(), "ldap")
			if err != nil {
				t.Fatalf("get target: %v", err)
			}

			switch {
			case testCase.ShouldUseKerberos && !target.UseKerberos:
				t.Errorf("target would not use Kerberos even though it should: %#v", testCase.Opts)
			case !testCase.ShouldUseKerberos && target.UseKerberos:
				t.Errorf("target would use Kerberos even though it should not: %#v", testCase.Opts)
			}
		})
	}
}

func TestCleanNTHash(t *testing.T) {
	ntHash := "31d6cfe0d16ae931b73c59d7e0c089c0"

	testCases := []string{
		ntHash,
		":" + ntHash,
		"aad3b435b51404eeaad3b435b51404ee:" + ntHash,
	}

	for i, testCase := range testCases {
		testCase := testCase

		t.Run(strconv.Itoa(i), func(t *testing.T) {
			creds, err := (&adauth.Options{
				User:   testUser + "@" + testDomain,
				NTHash: testCase,
			}).NoTarget()
			if err != nil {
				t.Fatalf("get credentials: %v", err)
			}

			if creds.NTHash != ntHash {
				t.Errorf("NT hash is %q instead of %q", creds.NTHash, ntHash)
			}
		})
	}
}
