package adauth

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/RedTeamPentesting/adauth/x509ext"
	"github.com/spf13/pflag"
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

	// It is possible to specify a cert/key pair directly, as PEM files or as a
	// single PFX file.
	Certificate     *x509.Certificate
	CertificateKey  any
	PFXFileName     string
	PFXPassword     string
	PEMCertFileName string
	PEMKeyFileName  string

	credential *Credential
	flagset    *pflag.FlagSet

	Debug    func(fmt string, a ...any)
	Resolver Resolver
}

// RegisterFlags registers authentication flags to a pflag.FlagSet such as the
// default flagset `pflag.CommandLine`.
func (opts *Options) RegisterFlags(flagset *pflag.FlagSet) {
	defaultCCACHEFile := os.Getenv("KRB5CCNAME")
	ccacheHint := ""

	if defaultCCACHEFile == "" {
		ccacheHint = " (defaults to $KRB5CCNAME, currently unset)"
	}

	flagset.StringVarP(&opts.User, "user", "u", "",
		"Username ('`user@domain`', 'domain\\user', 'domain/user' or 'user')")
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

	host, port, err := resolver.LookupFirstService(ctx, protocol, cred.Domain)
	if err != nil {
		lookupSRVErr := fmt.Errorf("could not lookup %q service of domain %q: %w", protocol, cred.Domain, err)

		dcAddr, err = resolver.LookupDCByDomain(ctx, cred.Domain)
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
		if err != nil {
			return nil, fmt.Errorf("stat CCache path: %w", err)
		} else if s.IsDir() {
			return nil, fmt.Errorf("CCache path is a directory: %s", opts.CCache)
		}

		ccache = opts.CCache
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

	switch {
	case opts.Certificate != nil && opts.CertificateKey == nil:
		return nil, fmt.Errorf("specify a key file for the client certificate")
	case opts.Certificate != nil && opts.CertificateKey != nil:
		cred.ClientCert = opts.Certificate
		cred.ClientCertKey = opts.CertificateKey
	case opts.PFXFileName != "":
		cert, key, caCerts, err := readPFX(opts.PFXFileName, opts.PFXPassword)
		if err != nil {
			return nil, err
		}

		cred.ClientCert = cert
		cred.ClientCertKey = key
		cred.CACerts = caCerts
	case opts.PEMCertFileName != "" && opts.PEMKeyFileName == "":
		return nil, fmt.Errorf("specify a key file for the client certificate")
	case opts.PEMCertFileName != "" && opts.PEMKeyFileName != "":
		cert, key, err := readPEMCertAndKey(opts.PEMCertFileName, opts.PEMKeyFileName)
		if err != nil {
			return nil, err
		}

		cred.ClientCert = cert
		cred.ClientCertKey = key
	}

	//nolint:nestif
	if cred.ClientCert != nil {
		user, domain, err := x509ext.UserAndDomainFromOtherNames(cred.ClientCert)
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

func readPFX(fileName string, password string) (*x509.Certificate, any, []*x509.Certificate, error) {
	pfxData, err := os.ReadFile(fileName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read PFX: %w", err)
	}

	key, cert, caCerts, err := DecodePFX(pfxData, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode PFX: %w", err)
	}

	return cert, key, caCerts, nil
}

func readPEMCertAndKey(certFileName string, certKeyFileName string) (*x509.Certificate, any, error) {
	certData, err := os.ReadFile(certFileName)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert file: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, nil, fmt.Errorf("could not PEM-decode certificate")
	}

	if block.Type != "" && !strings.Contains(strings.ToLower(block.Type), "certificate") {
		return nil, nil, fmt.Errorf("unexpected block type for certificate: %q", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	certKeyData, err := os.ReadFile(certKeyFileName)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert key file: %w", err)
	}

	block, _ = pem.Decode(certKeyData)
	if block == nil {
		return nil, nil, fmt.Errorf("could not PEM-decode certificate key")
	}

	if block.Type != "" && !strings.Contains(strings.ToLower(block.Type), "key") {
		return nil, nil, fmt.Errorf("unexpected block type for key: %q", block.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, pkcs1Err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if pkcs1Err == nil {
			return cert, key, nil
		}

		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}

	return cert, key, nil
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
