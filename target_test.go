package adauth_test

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/RedTeamPentesting/adauth"
)

func TestNewTarget(t *testing.T) {
	targetIP := net.ParseIP("10.0.0.1")
	targetPort := "1234"
	targetHostname := "computer.tld"
	resolver := &testResolver{
		HostToAddr: map[string][]net.IP{
			targetHostname: {targetIP},
		},
		AddrToHost: map[string][]string{
			targetIP.String(): {targetHostname},
		},
	}

	t.Run("hostname_from_ip", func(t *testing.T) {
		target := adauth.NewTarget("", targetIP.String())
		target.Resolver = resolver

		if target.Address() != targetIP.String() {
			t.Errorf("target address is %q instead of %q", target.Address(), targetIP.String())
		}

		hostname, err := target.Hostname(context.Background())
		if err != nil {
			t.Errorf("get hostname: %v", err)
		}

		if hostname != targetHostname {
			t.Errorf("hostname is %q instead of %q", hostname, targetHostname)
		}
	})

	t.Run("ip_from_hostname", func(t *testing.T) {
		target := adauth.NewTarget("", targetHostname)
		target.Resolver = resolver

		if target.Address() != targetHostname {
			t.Errorf("target address is %q instead of %q", target.Address(), targetIP.String())
		}

		ip, err := target.IP(context.Background())
		if err != nil {
			t.Errorf("get hostname: %v", err)
		}

		if ip.String() != targetIP.String() {
			t.Errorf("hostname is %q instead of %q", ip.String(), targetIP.String())
		}
	})

	t.Run("hostname_and_port", func(t *testing.T) {
		target := adauth.NewTarget("", net.JoinHostPort(targetHostname, targetPort))
		target.Resolver = resolver

		if target.Port != targetPort {
			t.Errorf("target port is %q instead of %q", target.Port, targetPort)
		}

		_, port, err := net.SplitHostPort(target.Address())
		if err != nil {
			t.Fatalf("split target.Address(): %v", err)
		}

		if port != targetPort {
			t.Errorf("target.Address() contains port %q instead of %q", port, targetPort)
		}
	})
	t.Run("ip_and_port", func(t *testing.T) {
		target := adauth.NewTarget("", net.JoinHostPort(targetIP.String(), targetPort))
		target.Resolver = resolver

		if target.Port != targetPort {
			t.Errorf("target port is %q instead of %q", target.Port, targetPort)
		}

		_, port, err := net.SplitHostPort(target.Address())
		if err != nil {
			t.Fatalf("split target.Address(): %v", err)
		}

		if port != targetPort {
			t.Errorf("target.Address() contains port %q instead of %q", port, targetPort)
		}
	})
}

func TestTargetAddressWithAndWithoutPort(t *testing.T) {
	targetHostname := "computer.tld"

	t.Run("with_port", func(t *testing.T) {
		target := adauth.NewTarget("ldap", targetHostname+":389")

		if target.Address() != targetHostname+":389" {
			t.Errorf("target.Address() is %q instead of %q", target.Address(), targetHostname)
		}

		if target.AddressWithoutPort() != targetHostname {
			t.Errorf("target.AddressWithoutPort() is %q instead of %q", target.AddressWithoutPort(), targetHostname)
		}
	})
	t.Run("without_port", func(t *testing.T) {
		target := adauth.NewTarget("ldap", targetHostname)

		if target.Address() != targetHostname {
			t.Errorf("target.Address() is %q instead of %q", target.Address(), targetHostname)
		}

		if target.AddressWithoutPort() != targetHostname {
			t.Errorf("target.AddressWithoutPort() is %q instead of %q", target.AddressWithoutPort(), targetHostname)
		}
	})
}

func TestNewTargetSPN(t *testing.T) {
	hostname := "computer.tld"

	testCases := []struct {
		InputProtocol string
		SPNProtocol   string
	}{
		{
			InputProtocol: "",
			SPNProtocol:   "host",
		},
		{
			InputProtocol: "ldaps",
			SPNProtocol:   "ldap",
		},
		{
			InputProtocol: "smb",
			SPNProtocol:   "cifs",
		},
		{
			InputProtocol: "foo",
			SPNProtocol:   "foo",
		},
		{
			InputProtocol: "http",
			SPNProtocol:   "http",
		},

		{
			InputProtocol: "https",
			SPNProtocol:   "http",
		},
	}

	for i, testCase := range testCases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			spn, err := adauth.NewTarget(testCase.InputProtocol, hostname).SPN(context.Background())
			if err != nil {
				t.Fatalf("SPN: %v", err)
			}

			expectedSPN := testCase.SPNProtocol + `/` + hostname

			if spn != expectedSPN {
				t.Fatalf("SPN for %q is %q instead of %q", testCase.InputProtocol, spn, expectedSPN)
			}
		})
	}
}
