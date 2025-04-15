package ldapauth

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/compat"
	"github.com/RedTeamPentesting/adauth/othername"
	"github.com/RedTeamPentesting/adauth/pkinit"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/go-ldap/ldap/v3"
	"github.com/oiweiwei/gokrb5.fork/v9/client"
	"github.com/spf13/pflag"
)

// Options holds LDAP specific options.
type Options struct {
	// LDAP scheme (ldap or ldaps).
	Scheme string
	// Verify indicates whether TLS verification should be performed.
	Verify bool
	// Timeout sets the request timeout for the LDAP connection.
	Timeout time.Duration
	// Debug can be set to enable debug output, for example with
	// adauth.NewDebugFunc(...).
	Debug func(string, ...any)
	// SimpleBind indicates that SimpleBind authentication should be used
	// instead of NTLM, Kerberos or mTLS. For this, a cleartext password is
	// required.
	SimpleBind bool
	// TLSConfig for LDAPS or LDAP+StartTLS. InsecureSkipVerify is ignored and
	// set according to Options.Verify. MaxVersion will be changed to 1.2 unless
	// Options.DisableChannelBinding is set.
	TLSConfig *tls.Config
	// DisableChannelBinding omits the TLS certificate hash in Kerberos and NTLM
	// authentication.
	DisableChannelBinding bool
	// StartTLS indicates that a TLS connection should be established even for
	// non-LDAPS connections before authenticating. For client-certificate
	// authentication on regular LDAP connections, StartTLS will be used even if
	// this option is disabled.
	StartTLS bool
	// DialOptions can be used to customize the connection. DialOptions is
	// ignored when a custom LDAPDialer is set.
	DialOptions []ldap.DialOpt
	// KerberosDialer is a custom dialer that is used to request Kerberos
	// tickets. DialContext is used if implemented.
	KerberosDialer adauth.Dialer
	// LDAPDialer is a custom dialer that is used to establish LDAP connections.
	// DialContext is used if implemented.
	LDAPDialer adauth.Dialer
}

// RegisterFlags registers LDAP specific flags to a pflag.FlagSet such as the
// default flagset pflag.CommandLine.
func (opts *Options) RegisterFlags(flagset *pflag.FlagSet) {
	flagset.StringVar(&opts.Scheme, "scheme", "ldaps", "Scheme (ldap or ldaps)")
	flagset.DurationVar(&opts.Timeout, "timeout", 5*time.Second, "LDAP connection timeout")
	flagset.BoolVar(&opts.SimpleBind, "simple-bind", false, "Authenticate with simple bind")
	flagset.BoolVar(&opts.Verify, "verify", false, "Verify LDAP TLS certificate")
	flagset.BoolVar(&opts.StartTLS, "start-tls", false,
		"Negotiate StartTLS before authenticating on regular LDAP connection")
}

// SetDialer configures a dialer for LDAP and Kerberos.
func (opts *Options) SetDialer(dialer adauth.Dialer) {
	opts.KerberosDialer = dialer
	opts.LDAPDialer = dialer
}

// Connect returns an authenticated LDAP connection to the domain controller's
// LDAP server.
func Connect(ctx context.Context, authOpts *adauth.Options, ldapOpts *Options) (conn *ldap.Conn, err error) {
	creds, target, err := authOpts.WithDCTarget(ctx, ldapOpts.Scheme)
	if err != nil {
		return nil, err
	}

	return ConnectTo(ctx, creds, target, ldapOpts)
}

// Connect returns an authenticated LDAP connection to the specified target.
func ConnectTo(
	ctx context.Context, creds *adauth.Credential, target *adauth.Target, ldapOpts *Options,
) (conn *ldap.Conn, err error) {
	opts := ldapOpts
	if opts.Debug == nil {
		opts.Debug = func(s string, a ...any) {}
	}

	opts.TLSConfig, err = TLSConfig(ldapOpts, creds.ClientCert, creds.ClientCertKey, creds.CACerts)
	if err != nil {
		return nil, fmt.Errorf("configure TLS: %w", err)
	}

	if !ldapOpts.TLSConfig.InsecureSkipVerify && net.ParseIP(target.AddressWithoutPort()) != nil {
		hostname, err := target.Hostname(ctx)
		if err != nil {
			return nil, fmt.Errorf("determine target hostname for TLS verification: %w", err)
		}

		opts.TLSConfig.ServerName = hostname
	}

	conn, err = connect(ctx, target, opts)
	if err != nil {
		return nil, err
	}

	if opts.Timeout == 0 {
		conn.SetTimeout(3 * time.Second)
	} else {
		conn.SetTimeout(opts.Timeout)
	}

	err = bind(ctx, conn, creds, target, opts)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func connect(ctx context.Context, target *adauth.Target, opts *Options) (conn *ldap.Conn, err error) {
	switch {
	case strings.EqualFold(opts.Scheme, "ldaps"):
		if target.Port == "" {
			target.Port = ldap.DefaultLdapsPort
		}

		if opts.LDAPDialer == nil {
			conn, err = ldap.DialURL("ldaps://"+target.Address(),
				append(opts.DialOptions, ldap.DialWithTLSConfig(opts.TLSConfig))...)
			if err != nil {
				return nil, fmt.Errorf("LDAPS dial: %w", err)
			}
		} else {
			tcpConn, err := adauth.AsContextDialer(opts.LDAPDialer).DialContext(ctx, "tcp", target.Address())
			if err != nil {
				return nil, fmt.Errorf("dial with custom dialer: %w", err)
			}

			tlsConn := tls.Client(tcpConn, opts.TLSConfig)

			err = tlsConn.Handshake()
			if err != nil {
				return nil, err
			}

			conn = ldap.NewConn(tlsConn, true)
			conn.Start()
		}

		opts.Debug("connected to LDAPS server %s", target.Address())

		return conn, nil
	case strings.EqualFold(opts.Scheme, "ldap"):
		if target.Port == "" {
			target.Port = ldap.DefaultLdapPort
		}

		if opts.LDAPDialer == nil {
			conn, err = ldap.DialURL("ldap://"+target.Address(), opts.DialOptions...)
			if err != nil {
				return nil, fmt.Errorf("LDAP dial: %w", err)
			}
		} else {
			tcpConn, err := adauth.AsContextDialer(opts.LDAPDialer).DialContext(ctx, "tcp", target.Address())
			if err != nil {
				return nil, fmt.Errorf("dial with custom dialer: %w", err)
			}

			conn = ldap.NewConn(tcpConn, false)
			conn.Start()
		}

		opts.Debug("connected to LDAP server %s", target.Address())

		if opts.StartTLS {
			err = conn.StartTLS(opts.TLSConfig)
			if err != nil {
				_ = conn.Close()

				return nil, fmt.Errorf("StartTLS: %w", err)
			}
		}

		return conn, nil
	default:
		return nil, fmt.Errorf("invalid scheme: %q", opts.Scheme)
	}
}

func bind(
	ctx context.Context, conn *ldap.Conn, creds *adauth.Credential, target *adauth.Target, opts *Options,
) (err error) {
	switch {
	case opts.SimpleBind:
		opts.Debug("authenticating using simple bind")

		if creds.Password == "" && !creds.PasswordIsEmtpyString {
			return fmt.Errorf("specify a password for simple bind")
		}

		_, err = conn.SimpleBind(&ldap.SimpleBindRequest{
			Username: creds.UPN(),
			Password: creds.Password,
		})
		if err != nil {
			return fmt.Errorf("simple bind: %w", err)
		}
	case !target.UseKerberos && creds.ClientCert == nil:
		opts.Debug("authenticating using NTLM bind")

		if !creds.PasswordIsEmtpyString && (creds.Password == "" && creds.NTHash == "") {
			return fmt.Errorf("no credentials available for NTLM")
		}

		bindRequest := &ldap.NTLMBindRequest{
			Domain:             creds.Domain,
			Username:           creds.Username,
			Password:           creds.Password,
			Hash:               creds.NTHash,
			AllowEmptyPassword: creds.PasswordIsEmtpyString,
		}

		tlsState, ok := conn.TLSConnectionState()
		if ok && !opts.DisableChannelBinding {
			bindRequest.Negotiator = ntlmNegotiatorWithChannelBinding(tlsState.PeerCertificates[0])
		}

		_, err = conn.NTLMChallengeBind(bindRequest)
		if err != nil {
			return fmt.Errorf("NTLM bind: %w", err)
		}
	case target.UseKerberos:
		authClient, err := kerberosClient(ctx, conn, creds, opts)
		if err != nil {
			return err
		}

		spn, err := target.SPN(ctx)
		if err != nil {
			return fmt.Errorf("build SPN: %w", err)
		}

		err = conn.GSSAPIBind(authClient, spn, creds.NTHash)
		if err != nil {
			return fmt.Errorf("GSSAPI bind: %w", err)
		}
	case creds.ClientCert != nil && strings.EqualFold(opts.Scheme, "ldap"):
		opts.Debug("authenticating with client certificate via StartTLS")

		_, ok := conn.TLSConnectionState()
		if !ok {
			err = conn.StartTLS(opts.TLSConfig)
			if err != nil {
				return fmt.Errorf("StartTLS: %w", err)
			}
		}

		err = conn.ExternalBind()
		if err != nil {
			if creds.ClientCert.Issuer.CommonName == "" ||
				strings.EqualFold(creds.ClientCert.Subject.CommonName, creds.ClientCert.Issuer.CommonName) {
				return fmt.Errorf("external bind: %w "+
					"(certificate likely belongs to a KeyCredentialLink, try PKINIT with -k instead)", err)
			}

			return fmt.Errorf("external bind: %w", err)
		}
	case creds.ClientCert != nil:
		opts.Debug("authenticating with client certificate")

		res, err := conn.WhoAmI(nil)
		if err != nil {
			return fmt.Errorf("send whoami to verify certificate authentication: %w", err)
		}

		if res.AuthzID == "" {
			if creds.ClientCert.Issuer.CommonName == "" ||
				strings.EqualFold(creds.ClientCert.Subject.CommonName, creds.ClientCert.Issuer.CommonName) {
				return fmt.Errorf("client certificate authentication failed " +
					"(certificate likely belongs to a KeyCredentialLink, try PKINIT with -k instead)")
			}

			return fmt.Errorf("client certificate authentication failed")
		}
	default:
		return fmt.Errorf("no credentials available")
	}

	return nil
}

func kerberosClient(
	ctx context.Context, conn *ldap.Conn, creds *adauth.Credential, opts *Options,
) (*gssapiClient, error) {
	krbConf, err := creds.KerberosConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("configure Kerberos: %w", err)
	}

	if opts.KerberosDialer == nil {
		opts.KerberosDialer = &net.Dialer{Timeout: pkinit.DefaultKerberosRoundtripDeadline}
	}

	var (
		authClient *gssapiClient
		cert       *x509.Certificate
	)

	tlsState, ok := conn.TLSConnectionState()
	if ok && !opts.DisableChannelBinding {
		cert = tlsState.PeerCertificates[0]
	}

	switch {
	case creds.Password != "" || creds.PasswordIsEmtpyString:
		opts.Debug("authenticating using GSSAPI bind (password)")

		authClient = &gssapiClient{
			Client: client.NewWithPassword(
				creds.Username,
				strings.ToUpper(creds.Domain),
				creds.Password,
				compat.Gokrb5ForkV9KerberosConfig(krbConf),
				client.DisablePAFXFAST(true),
				client.Dialer(opts.KerberosDialer),
			),
		}

		authClient.BindCertificate = cert
	case creds.NTHash != "" || creds.AESKey != "":
		opts.Debug("authenticating using GSSAPI bind (key)")

		keyTab, err := creds.Keytab()
		if err != nil {
			return nil, fmt.Errorf("create keytab: %w", err)
		}

		authClient = &gssapiClient{
			Client: client.NewWithKeytab(
				creds.Username,
				strings.ToUpper(creds.Domain),
				compat.Gokrb5ForkV9Keytab(keyTab),
				compat.Gokrb5ForkV9KerberosConfig(krbConf),
				client.DisablePAFXFAST(true),
				client.Dialer(opts.KerberosDialer),
			),
			BindCertificate: cert,
		}

		authClient.BindCertificate = cert
	case creds.ClientCert != nil:
		opts.Debug("authenticating using GSSAPI bind (PKINIT)")

		return newPKINITClient(ctx, creds.Username, strings.ToUpper(creds.Domain),
			creds.ClientCert, creds.ClientCertKey, krbConf, opts.KerberosDialer)
	case creds.CCache != "":
		opts.Debug("authenticating using GSSAPI bind (ccache)")

		authClient, err = newClientFromCCache(
			creds.Username, strings.ToUpper(creds.Domain), creds.CCache, krbConf, opts.KerberosDialer)
		if err != nil {
			return nil, fmt.Errorf("create GSSAPI client from CCACHE: %w", err)
		}

		authClient.BindCertificate = cert
	default:
		return nil, fmt.Errorf("no credentials available for Kerberos")
	}

	return authClient, nil
}

// TLSConfig returns a TLS config based on the default config in the provided
// LDAP options as well as PFX files.
func TLSConfig(
	opts *Options, clientCert *x509.Certificate, clientCertKey crypto.PrivateKey, caCerts []*x509.Certificate,
) (*tls.Config, error) {
	tlsConfig := opts.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	tlsConfig.InsecureSkipVerify = !opts.Verify
	if tlsConfig.MaxVersion == 0 && !opts.DisableChannelBinding {
		tlsConfig.MaxVersion = tls.VersionTLS12 // channel binding is not supported for TLS1.3
	}

	if clientCert == nil {
		return tlsConfig, nil
	}

	var (
		keyBytes []byte
		err      error
	)

	switch v := clientCertKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, *ecdh.PrivateKey:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(v)
		if err != nil {
			return nil, fmt.Errorf("marshal private key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported client certificate key type: %T", clientCertKey)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCert.Raw,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	clientCertificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}

	tlsConfig.Certificates = append(tlsConfig.Certificates, clientCertificate)

	if len(caCerts) == 0 {
		return tlsConfig, nil
	}

	if tlsConfig.RootCAs == nil {
		tlsConfig.RootCAs = x509.NewCertPool()
	}

	for _, cert := range caCerts {
		tlsConfig.RootCAs.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}))
	}

	return tlsConfig, nil
}

// UserAndDomainFromPFX extracts the username and domain from UPNs in the
// certificate's otherName SAN extension.
func UserAndDomainFromPFX(pfxFile string, password string) (user string, domain string, err error) {
	pfxData, err := os.ReadFile(pfxFile)
	if err != nil {
		return "", "", fmt.Errorf("read PFX: %w", err)
	}

	_, cert, _, err := pkcs12.DecodeChain(pfxData, password)
	if err != nil {
		return "", "", fmt.Errorf("decode PFX: %w", err)
	}

	user, domain = userAndDomainFromCert(cert)

	return user, domain, nil
}

func userAndDomainFromCert(cert *x509.Certificate) (user string, domain string) {
	upns, err := othername.UPNs(cert)
	if err != nil {
		return "", ""
	}

	for _, upn := range upns {
		if !strings.Contains(upn, "@") {
			continue
		}

		parts := strings.Split(upn, "@")
		if len(parts) != 2 {
			continue
		}

		return parts[0], parts[1]
	}

	return "", ""
}

// ChannelBinding hash computes the channel binding token that can be included
// in the authentication handshake to make sure that the client has established
// a TLS connection to the correct server.
func ChannelBindingHash(cert *x509.Certificate) []byte {
	hashType := crypto.SHA256

	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		hashType = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		hashType = crypto.SHA512
	}

	certHasher := hashType.New()
	_, _ = certHasher.Write(cert.Raw)
	certHash := certHasher.Sum(nil)
	prefix := "tls-server-end-point:"

	// https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_channel_bindings
	// https://github.com/jborean93/Mailozaurr/blob
	//     /6b565c4a1debdf301a95b93674ff12acdf8c762c/Classes/Class.SaslMechanismWindowsAuth.ps1#L67C19-L68C1
	channelBindingStructure := []byte{
		0, 0, 0, 0, // InitiatorAddrType
		0, 0, 0, 0, // InitiatorLength

		0, 0, 0, 0, // AcceptorAddrType,
		0, 0, 0, 0, // AcceptorLength,
	}

	channelBindingStructure = binary.LittleEndian.AppendUint32(channelBindingStructure,
		uint32(len(prefix)+len(certHash))) // ApplicationDataLength
	channelBindingStructure = append(channelBindingStructure, []byte(prefix)...)
	channelBindingStructure = append(channelBindingStructure, certHash...)

	channelBindingHasher := md5.New()
	channelBindingHasher.Write(channelBindingStructure)

	hash := channelBindingHasher.Sum(nil)

	return hash
}
