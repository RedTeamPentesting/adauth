package adauth_test

import (
	"context"
	"fmt"
	"net"

	"github.com/RedTeamPentesting/adauth"
)

type testResolver struct {
	HostToAddr map[string][]net.IP
	AddrToHost map[string][]string
	SRV        map[string]map[string]map[string]struct {
		Name string
		SRV  []*net.SRV
	}
	Error error
}

func (r *testResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if r.Error != nil {
		return nil, r.Error
	}

	if r.AddrToHost == nil {
		return nil, nil
	}

	return r.AddrToHost[addr], nil
}

func (r *testResolver) LookupIP(ctx context.Context, network string, host string) ([]net.IP, error) {
	if r.Error != nil {
		return nil, r.Error
	}

	if r.HostToAddr == nil {
		return nil, nil
	}

	addrs := r.HostToAddr[host]

	switch network {
	case "ip":
		return addrs, nil
	case "ip4":
		var ipv4s []net.IP

		for _, addr := range addrs {
			if addr.To4() != nil {
				ipv4s = append(ipv4s, addr)
			}
		}

		return ipv4s, nil
	case "ip6":
		var ipv6s []net.IP

		for _, addr := range addrs {
			if addr.To4() == nil {
				ipv6s = append(ipv6s, addr)
			}
		}

		return ipv6s, nil
	default:
		return nil, fmt.Errorf("invalid network: %q", network)
	}
}

func (r *testResolver) LookupSRV(
	ctx context.Context, service string, proto string, name string,
) (string, []*net.SRV, error) {
	if r.Error != nil {
		return "", nil, r.Error
	}

	if r.SRV == nil {
		return "", nil, nil
	}

	srvForService := r.SRV[service]
	if srvForService == nil {
		return "", nil, nil
	}

	srvForServiceAndProto := srvForService[proto]
	if srvForServiceAndProto == nil {
		return "", nil, nil
	}

	record := srvForServiceAndProto[name]

	return record.Name, record.SRV, nil
}

var _ adauth.Resolver = &testResolver{}
