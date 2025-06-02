package adauth

import (
	"context"
	"fmt"
	"net"
	"strings"
)

type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIP(ctx context.Context, network string, host string) ([]net.IP, error)
	LookupSRV(ctx context.Context, service string, proto string, name string) (string, []*net.SRV, error)
}

var _ Resolver = net.DefaultResolver

type resolver struct {
	Resolver
	debugFn func(string, ...any)
}

func ensureResolver(r Resolver, debug func(string, ...any)) *resolver {
	if r == nil {
		return &resolver{Resolver: net.DefaultResolver, debugFn: debug}
	}

	return &resolver{Resolver: r, debugFn: debug}
}

func (r *resolver) debug(format string, a ...any) {
	if r.debugFn == nil {
		return
	}

	r.debugFn(format, a...)
}

func (r *resolver) LookupFirstService(ctx context.Context, protocol string, domain string) (string, int, error) {
	_, addrs, err := r.Resolver.LookupSRV(ctx, protocol, "tcp", domain)
	if err != nil {
		if strings.EqualFold(protocol, "ldaps") {
			host, _, srvLDAPErr := r.LookupFirstService(ctx, "ldap", domain)
			if srvLDAPErr == nil {
				return host, 636, nil
			}
		}

		return "", 0, fmt.Errorf("lookup %q service of domain %q: %w", protocol, domain, err)
	}

	if len(addrs) == 0 {
		return "", 0, fmt.Errorf("no %q services were discovered for domain %q", protocol, domain)
	}

	return strings.TrimRight(addrs[0].Target, "."), int(addrs[0].Port), nil
}

func (r *resolver) LookupDCByDomain(ctx context.Context, domain string) (string, error) {
	// Unfortunately, Go does not implement SOA lookups, so we lookup the domain
	// for DC IPs and reverse lookup their hostnames instead.
	dcAddrs, err := r.LookupIP(context.Background(), "ip", domain)
	if err != nil {
		return "", fmt.Errorf("lookup domain itself: %w", err)
	}

	if len(dcAddrs) == 0 {
		return "", fmt.Errorf("looking up domain itself returned no results")
	}

	dcAddr := dcAddrs[0].String()

	names, err := r.LookupAddr(context.Background(), dcAddr)
	if err == nil {
		domain, names = splitResultsInDomainAndHostname(names, domain)

		switch {
		case len(names) > 0:
			dcAddr = strings.TrimRight(names[0], ".")
		case domain != "":
			dcAddr = domain

			r.debug("Warning: reverse lookup of DC only returned domain name, using domain name %q as DC hostname",
				domain)
		default:
			r.debug("Warning: reverse lookup of DC did not contain a hostname")
		}
	} else {
		r.debug("Warning: could not reverse lookup DC IP: %v", err)
	}

	return dcAddr, nil
}

// A reverse lookup of the DC IP returns both the DCs hostname and the name of
// the domain. This function splits the results in these categories.
func splitResultsInDomainAndHostname(
	hostnames []string, domain string,
) (domainFromHostnames string, filtered []string) {
	var d string

	for _, hostname := range hostnames {
		hostname = strings.TrimRight(hostname, ".")

		if strings.EqualFold(hostname, domain) {
			d = hostname
		} else {
			filtered = append(filtered, hostname)
		}
	}

	return d, filtered
}
