package adauth

import (
	"context"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/RedTeamPentesting/adauth/othername"
	"github.com/spf13/pflag"
	"software.sslmate.com/src/go-pkcs12"
)

// Options holds command line options that are used to determine authentication
// credentials and target.
type Options struct {
	// Username (with domain) in one of the following formats:
	// `UPN`, `domain\user`, `domain/user` or `user`
	User             string
	Password         string
	NTHash           string
	AESKey           string
	CCache           string
	DomainController string
	ForceKerberos    bool
	PFXFileName      string
	PFXPassword      string

	credential *Credential
	flagset    *pflag.FlagSet

	Debug    func(fmt string, a ...any)
	Resolver Resolver
}

// AuxiliaryInfo represents information that was obtained elsewhere that can be
// used to supplement the parsed options. However, parsed options always take
// precedent.
type AuxiliaryInfo struct {
	Domain string
	User   string
	DC     string
}

// RegisterFlags registers authentication flags to a pflag.FlagSet such as the
// default flagset `pflag.CommandLine`.
func (opts *Options) RegisterFlags(flagset *pflag.FlagSet) {
	defaultCCACHEFile := os.Getenv("KRB5CCNAME")
	ccacheHint := ""

	if defaultCCACHEFile == "" {
		ccacheHint = " (defaults to $KRB5CCNAME, currently unset)"
	}

	flagset.StringVarP(&opts.User, "user", "u", "", "Username ('`user@domain`', 'domain\\user', 'domain/user' or 'user')")
	flagset.StringVarP(&opts.Password, "password", "p", "", "Password")
	flagset.StringVarP(&opts.NTHash, "nt-hash", "H", "", "NT `hash` ('NT', ':NT' or 'LM:NT')")
	flagset.StringVar(&opts.AESKey, "aes-key", "", "Kerberos AES `hex key`")
	flagset.StringVar(&opts.PFXFileName, "pfx", "", "Client certificate and private key as PFX `file`")
	flagset.StringVar(&opts.PFXPassword, "pfx-password", "", "Password for PFX file")
	flagset.StringVar(&opts.CCache, "ccache", defaultCCACHEFile, "Kerberos CCache `file` name"+ccacheHint)
	flagset.StringVar(&opts.DomainController, "dc", "", "Domain controller")
	flagset.BoolVarP(&opts.ForceKerberos, "kerberos", "k", false, "Use Kerberos authentication")
	opts.flagset = flagset
}

func (opts *Options) debug(format string, a ...any) {
	if opts.Debug != nil {
		opts.Debug(format, a...)
	}
}

func portForProtocol(protocol string) string {
	switch strings.ToLower(protocol) {
	case "ldap":
		return "389"
	case "ldaps":
		return "636"
	case "http":
		return "80"
	case "https":
		return "443"
	case "smb":
		return "445"
	case "rdp":
		return "3389"
	case "kerberos":
		return "88"
	default:
		return ""
	}
}

func addPortForProtocolIfMissing(protocol string, addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port != "" {
		return addr
	}

	port = portForProtocol(protocol)
	if port == "" {
		return addr
	}

	return net.JoinHostPort(host, port)
}

// WithDCTarget returns credentials and the domain controller for the
// corresponding domain as the target.
func (opts *Options) WithDCTarget(ctx context.Context, protocol string) (*Credential, *Target, error) {
	if opts.DomainController != "" {
		return opts.WithTarget(ctx, protocol, addPortForProtocolIfMissing(protocol, opts.DomainController))
	}

	cred, err := opts.preliminaryCredential()
	if err != nil {
		return nil, nil, err
	}

	if cred.Domain == "" {
		return nil, nil, fmt.Errorf("domain unknown")
	}

	resolver := ensureResolver(opts.Resolver, opts.debug)

	var dcAddr string

	host, port, err := resolver.LookupFirstService(context.Background(), protocol, cred.Domain)
	if err != nil {
		lookupSRVErr := fmt.Errorf("could not lookup %q service of domain %q: %w", protocol, cred.Domain, err)

		dcAddr, err = resolver.LookupDCByDomain(context.Background(), cred.Domain)
		if err != nil {
			return nil, nil, fmt.Errorf("could not find DC: %w and %w", lookupSRVErr, err)
		}

		port := portForProtocol(protocol)
		if port != "" {
			dcAddr = net.JoinHostPort(dcAddr, port)
		}

		opts.debug("using DC %s based on domain lookup for %s", dcAddr, cred.Domain)
	} else {
		dcAddr = net.JoinHostPort(host, strconv.Itoa(port))
		opts.debug("using DC %s based on SRV lookup for domain %s", dcAddr, cred.Domain)
	}

	return cred, newTarget(
		protocol, dcAddr, opts.ForceKerberos || cred.mustUseKerberos(), opts.CCache, opts.Resolver), nil
}

// WithTarget returns credentials and the specified target.
func (opts *Options) WithTarget(ctx context.Context, protocol string, target string) (*Credential, *Target, error) {
	if protocol == "" {
		protocol = "host"
	}

	cred, err := opts.preliminaryCredential()
	if err != nil {
		return nil, nil, err
	}

	t := newTarget(protocol, target, opts.ForceKerberos || cred.mustUseKerberos(), opts.CCache, opts.Resolver)

	if cred.Domain == "" {
		hostname, err := t.Hostname(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("lookup target hostname to determine domain: %w", err)
		}

		parts := strings.SplitN(hostname, ".", 2)
		if len(parts) == 2 {
			switch {
			case strings.Contains(parts[1], "."):
				cred.Domain = parts[1]
			default:
				cred.Domain = hostname
			}
		}
	}

	return cred, t, nil
}

// Username returns the user's name. Username may return an empty string.
func (opts *Options) Username() string {
	cred, err := opts.preliminaryCredential()
	if err != nil {
		return ""
	}

	return cred.Username
}

// UPN returns the user's domain. Domain may return an empty string.
func (opts *Options) Domain() string {
	cred, err := opts.preliminaryCredential()
	if err != nil {
		return ""
	}

	return cred.Domain
}

// UPN returns the user's universal principal name. UPN may return an empty
// string.
func (opts *Options) UPN() string {
	cred, err := opts.preliminaryCredential()
	if err != nil {
		return ""
	}

	return cred.UPN()
}

// NoTarget returns the user credentials without supplementing it with
// information from a target.
func (opts *Options) NoTarget() (*Credential, error) {
	return opts.preliminaryCredential()
}

func (opts *Options) preliminaryCredential() (*Credential, error) {
	if opts.credential != nil {
		return opts.credential, nil
	}

	domain, username := splitUserIntoDomainAndUsername(opts.User)

	cleanedNTHash := cleanNTHash(opts.NTHash)

	var ntHash string

	if cleanedNTHash != "" {
		ntHashBytes, err := hex.DecodeString(cleanedNTHash)
		if err != nil {
			return nil, fmt.Errorf("invalid NT hash: parse hex: %w", err)
		} else if len(ntHashBytes) != 16 {
			return nil, fmt.Errorf("invalid NT hash: %d bytes instead of 16", len(ntHashBytes))
		}

		ntHash = cleanedNTHash
	}

	var aesKey string

	if opts.AESKey != "" {
		aesKeyBytes, err := hex.DecodeString(opts.AESKey)
		if err != nil {
			return nil, fmt.Errorf("invalid AES key: parse hex: %w", err)
		} else if len(aesKeyBytes) != 16 && len(aesKeyBytes) != 32 {
			return nil, fmt.Errorf("invalid AES key: %d bytes instead of 16 or 32", len(aesKeyBytes))
		}

		aesKey = opts.AESKey
	}

	var ccache string

	if opts.CCache != "" {
		s, err := os.Stat(opts.CCache)
		if err == nil && !s.IsDir() {
			ccache = opts.CCache
		}
	}

	cred := &Credential{
		Username:              username,
		Password:              opts.Password,
		Domain:                domain,
		NTHash:                cleanNTHash(ntHash),
		AESKey:                aesKey,
		CCache:                ccache,
		dc:                    opts.DomainController,
		PasswordIsEmtpyString: opts.Password == "" && (opts.flagset != nil && opts.flagset.Changed("password")),
		CCacheIsFromEnv:       opts.CCache != "" && (opts.flagset != nil && !opts.flagset.Changed("ccache")),
		Resolver:              opts.Resolver,
	}

	if opts.PFXFileName != "" {
		pfxData, err := os.ReadFile(opts.PFXFileName)
		if err != nil {
			return nil, fmt.Errorf("read PFX: %w", err)
		}

		key, cert, caCerts, err := pkcs12.DecodeChain(pfxData, opts.PFXPassword)
		if err != nil {
			return nil, fmt.Errorf("decode PFX: %w", err)
		}

		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PFX key is not an RSA private key but %T", rsaKey)
		}

		cred.ClientCert = cert
		cred.ClientCertKey = rsaKey
		cred.CACerts = caCerts
	}

	//nolint:nestif
	if cred.ClientCert != nil {
		user, domain, err := othername.UserAndDomain(cred.ClientCert)
		if err == nil {
			if cred.Username == "" {
				cred.Username = user
			}

			if cred.Domain == "" {
				cred.Domain = domain
			}
		}
	}

	opts.credential = cred

	return cred, nil
}

// NewDebugFunc creates a debug output handler.
func NewDebugFunc(enabled *bool, writer io.Writer, colored bool) func(string, ...any) {
	return func(format string, a ...any) {
		if enabled == nil || !*enabled {
			return
		}

		format = strings.TrimRight(format, "\n")
		if colored {
			format = "\033[2m" + format + "\033[0m"
		}

		_, _ = fmt.Fprintf(writer, format+"\n", a...)
	}
}

func cleanNTHash(h string) string {
	if !strings.Contains(h, ":") {
		return h
	}

	parts := strings.Split(h, ":")
	if len(parts) != 2 {
		return h
	}

	return parts[1]
}
