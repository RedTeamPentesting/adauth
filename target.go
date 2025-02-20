package adauth

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Target holds information about the authentication target.
type Target struct {
	// Port holds the target's port which may be empty.
	Port     string
	addr     string
	hostname string
	ip       net.IP
	// UseKerberos indicated that Kerberos authentication should be used to
	// authenticate to this target.
	//
	// Warning: `UseKerberos` is false when the only credential available is a
	// client certificate because in this case mTLS may also be used to
	// authenticate depending on the protocol (e.g. LDAP/HTTPS). If the protocol
	// that is used does not support using client certificates directly, you
	// should decide for Kerberos authentication if `target.UserKerberos &&
	// creds.ClientCert != nil` is `true`. In this case, Kerberos with PKINIT
	// will be used.
	UseKerberos bool
	// Protocol is a string that represents the protocol that is used when
	// communicating with this target. It is used to construct the SPN, however,
	// some protocol name corrections may be applied in this case, such as 'smb'
	// -> 'cifs'.
	Protocol string
	ccache   string

	// Resolver can be used to set an alternative DNS resolver. If empty,
	// net.DefaultResolver is used.
	Resolver Resolver
}

// NewTarget creates a new target. The provided protocol is used to construct
// the SPN, however, some protocol name corrections may be applied in this case,
// such as 'smb' -> 'cifs'. The target parameter may or may not contain a port
// and the protocol string will *not* influence the port of the resulting
// Target.
func NewTarget(protocol string, target string) *Target {
	return newTarget(protocol, target, false, "", nil)
}

func newTarget(protocol string, target string, useKerberos bool, ccache string, resolver Resolver) *Target {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}

	t := &Target{
		addr:        host,
		Port:        port,
		Protocol:    protocol,
		UseKerberos: useKerberos,
		ccache:      ccache,
		Resolver:    resolver,
	}

	ip := net.ParseIP(host)
	if ip == nil {
		t.hostname = host
	} else {
		t.ip = ip
	}

	return t
}

// Address returns the address including the port if available. It will contain
// either a hostname or an IP address depending on how the target was
// constructed.
func (t *Target) Address() string {
	if t.Port != "" {
		return net.JoinHostPort(t.addr, t.Port)
	} else {
		return t.addr
	}
}

// AddressWithoutPort is like Address but without the port.
func (t *Target) AddressWithoutPort() string {
	return t.addr
}

// IP returns the target's IP address. If only the hostname is known, a lookup
// will be performed.
func (t *Target) IP(ctx context.Context) (net.IP, error) {
	if t.ip != nil {
		return t.ip, nil
	}

	if t.hostname == "" {
		return nil, fmt.Errorf("no IP or hostname known")
	}

	addrs, err := ensureResolver(t.Resolver, nil).LookupIP(ctx, "ip", t.hostname)

	switch {
	case err != nil:
		return nil, fmt.Errorf("lookup %s: %w", t.hostname, err)
	case len(addrs) > 1:
		return nil, fmt.Errorf("lookup of %s returned multiple names", t.hostname)
	case len(addrs) == 0:
		return nil, fmt.Errorf("lookup of %s returned no names", t.hostname)
	}

	t.ip = addrs[0]

	return addrs[0], nil
}

// Hostname returns the target's hostname. If only the IP address is known, a
// lookup will be performed.
func (t *Target) Hostname(ctx context.Context) (string, error) {
	if t.hostname != "" {
		return t.hostname, nil
	}

	if t.ip == nil {
		return "", fmt.Errorf("no IP or hostname known")
	}

	names, err := ensureResolver(t.Resolver, nil).LookupAddr(ctx, t.ip.String())

	switch {
	case err != nil:
		return "", fmt.Errorf("reverse lookup %s: %w", t.ip, err)
	case len(names) > 1:
		return "", fmt.Errorf("reverse lookup of %s returned multiple names", t.ip)
	case len(names) == 0:
		return "", fmt.Errorf("reverse lookup of %s returned no names", t.ip)
	}

	t.hostname = strings.TrimRight(names[0], ".")

	return t.hostname, nil
}

// SPN returns the target's service principal name. The protocol part of the SPN
// *may* be changed to the generic 'host' in order to align with the SPN of
// service tickets in a CCACHE file. Some protocol name translations will also
// be applied such as 'smb' -> 'cifs'.
func (t *Target) SPN(ctx context.Context) (string, error) {
	hostname, err := t.Hostname(ctx)
	if err != nil {
		return "", err
	}

	var spn string

	switch strings.ToLower(t.Protocol) {
	case "smb":
		spn = "cifs/" + hostname
	case "ldap", "ldaps":
		spn = "ldap/" + hostname
	case "http", "https":
		spn = "http/" + hostname
	case "kerberos":
		spn = "krbtgt"
	case "":
		spn = "host/" + hostname
	default:
		spn = t.Protocol + `/` + hostname
	}

	if t.ccache == "" || strings.HasPrefix(spn, "host/") {
		return spn, nil
	}

	ccache, err := credentials.LoadCCache(t.ccache)
	if err != nil {
		return spn, nil //nolint:nilerr
	}

	_, ok := ccache.GetEntry(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn))
	if ok {
		return spn, nil
	}

	// change SPN to generic host SPN if a ticket exists ONLY for the generic host SPN
	_, ok = ccache.GetEntry(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "host/"+hostname))
	if ok {
		return "host/" + hostname, nil
	}

	return spn, nil
}
