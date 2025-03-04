package adauth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/RedTeamPentesting/adauth/othername"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"software.sslmate.com/src/go-pkcs12"
)

// Credential represents Active Directory credentials.
type Credential struct {
	// Username is the username without the domain.
	Username string
	// Password contains the users cleartext password if available.
	Password string
	// Domain holds the user's domain.
	Domain string
	// NTHash holds the user's NT hash or Kerberos RC4 key if available.
	NTHash string
	// AESKey holds the user's Kerberos AES128 or AES256 key if available.
	AESKey string
	// CCache contains the path to the user's CCache file.
	CCache string
	// ClientCert holds a client certificate for Kerberos or LDAP authentication if available.
	ClientCert *x509.Certificate
	// ClientCertKey holds the private key that corresponds to ClientCert.
	ClientCertKey *rsa.PrivateKey
	// CACerts holds CA certificates that were loaded alongside the ClientCert.
	CACerts []*x509.Certificate
	dc      string
	// PasswordIsEmptyString is true when an empty Password field should not be
	// interpreted as a missing password but as a password that happens to be
	// empty.
	PasswordIsEmtpyString bool
	// CCacheIsFromEnv indicates whether the CCache was set explicitly or
	// implicitly through an environment variable.
	CCacheIsFromEnv bool

	// Resolver can be used to set an alternative DNS resolver. If empty,
	// net.DefaultResolver is used.
	Resolver Resolver
}

// CredentialFromPFX creates a Credential structure for certificate-based
// authentication based on a PFX file.
func CredentialFromPFX(
	username string, domain string, pfxFile string, pfxPassword string,
) (*Credential, error) {
	pfxData, err := os.ReadFile(pfxFile)
	if err != nil {
		return nil, fmt.Errorf("read PFX: %w", err)
	}

	return CredentialFromPFXBytes(username, domain, pfxData, pfxPassword)
}

// CredentialFromPFX creates a Credential structure for certificate-based
// authentication based on PFX data.
func CredentialFromPFXBytes(
	username string, domain string, pfxData []byte, pfxPassword string,
) (*Credential, error) {
	cred := &Credential{
		Username: username,
		Domain:   domain,
	}

	key, cert, caCerts, err := pkcs12.DecodeChain(pfxData, pfxPassword)
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

	user, domain, err := othername.UserAndDomain(cert)
	if err == nil {
		if cred.Username == "" {
			cred.Username = user
		}

		if cred.Domain == "" {
			cred.Domain = domain
		}
	}

	return cred, nil
}

// UPN is the user principal name (username@domain).
func (c *Credential) UPN() string {
	return c.Username + "@" + c.Domain
}

// LogonName is the legacy logon name (domain\username).
func (c *Credential) LogonName() string {
	return c.Domain + `\` + c.Username
}

// LogonNameWithUpperCaseDomain is like LogonName with the domain capitalized
// for compatibility with the Kerberos library (DOMAIN\username).
func (c *Credential) LogonNameWithUpperCaseDomain() string {
	return strings.ToUpper(c.Domain) + `\` + c.Username
}

// ImpacketLogonName is the Impacket-style logon name (domain/username).
func (c *Credential) ImpacketLogonName() string {
	return c.Domain + "/" + c.Username
}

// SetDC configures a specific domain controller for this credential.
func (c *Credential) SetDC(dc string) {
	c.dc = dc
}

// DC returns the domain controller of the credential's domain as a target.
func (c *Credential) DC(ctx context.Context, protocol string) (*Target, error) {
	if c.dc != "" {
		return newTarget(protocol, c.dc, true, c.CCache, c.Resolver), nil
	}

	if c.Domain == "" {
		return nil, fmt.Errorf("domain unknown")
	}

	_, addrs, err := ensureResolver(c.Resolver, nil).LookupSRV(ctx, "kerberos", "tcp", c.Domain)
	if err != nil {
		return nil, fmt.Errorf("lookup %q service of domain %q: %w", "kerberos", c.Domain, err)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no %q services were discovered for domain %q", "kerberos", c.Domain)
	}

	return newTarget(protocol, strings.TrimRight(addrs[0].Target, "."), true, c.CCache, c.Resolver), nil
}

func (c *Credential) mustUseKerberos() bool {
	return c.Password == "" && c.NTHash == "" && (c.CCache != "" || c.AESKey != "")
}

// Keytab returns the Kerberos keytab containing the AES key and/or NT hash if
// they were supplied. If a password is supplied, the keys/hashes are not
// derived and the keytab will be empty. For compatibility with other Kerberos
// libraries, see the `compat` package.
func (c *Credential) Keytab() (*keytab.Keytab, error) {
	kt := newKeytab()

	if c.AESKey != "" {
		err := addKeyToKeytab(kt, c.Username, c.Domain, c.AESKey, true, 1)
		if err != nil {
			return nil, fmt.Errorf("add AES key: %w", err)
		}
	}

	if c.NTHash != "" {
		err := addKeyToKeytab(kt, c.Username, c.Domain, c.NTHash, false, 1)
		if err != nil {
			return nil, fmt.Errorf("add RC4 key: %w", err)
		}
	}

	return kt, nil
}

// KerberosConfig returns the Kerberos configuration for the credential's
// domain. For compatibility with other Kerberos libraries, see the `compat`
// package.
func (c *Credential) KerberosConfig(ctx context.Context) (*config.Config, error) {
	dc, err := c.DC(ctx, "krbtgt")
	if err != nil {
		return nil, fmt.Errorf("find DC: %w", err)
	}

	krbConf := config.New()
	krbConf.LibDefaults.DefaultRealm = strings.ToUpper(c.Domain)
	krbConf.LibDefaults.AllowWeakCrypto = true
	krbConf.LibDefaults.DNSLookupRealm = false
	krbConf.LibDefaults.DNSLookupKDC = false
	krbConf.LibDefaults.TicketLifetime = time.Duration(24) * time.Hour
	krbConf.LibDefaults.RenewLifetime = time.Duration(24*7) * time.Hour
	krbConf.LibDefaults.Forwardable = true
	krbConf.LibDefaults.Proxiable = true
	krbConf.LibDefaults.RDNS = false
	krbConf.LibDefaults.UDPPreferenceLimit = 1 // Force use of tcp

	if c.NTHash != "" {
		// use RC4 for pre-auth but AES256 for ephemeral keys, otherwise we get
		// unsupported GSSAPI tokens during LDAP SASL handshake
		krbConf.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96}
		krbConf.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.RC4_HMAC}
		krbConf.LibDefaults.PermittedEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96}
		krbConf.LibDefaults.PreferredPreauthTypes = []int{int(etypeID.RC4_HMAC)}
	} else {
		krbConf.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96}
		krbConf.LibDefaults.DefaultTktEnctypeIDs = []int32{
			etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC,
		}
		krbConf.LibDefaults.PermittedEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96}
		krbConf.LibDefaults.PreferredPreauthTypes = []int{
			int(etypeID.AES256_CTS_HMAC_SHA1_96), int(etypeID.AES128_CTS_HMAC_SHA1_96), int(etypeID.RC4_HMAC),
		}
	}

	krbConf.Realms = []config.Realm{
		{
			Realm:         strings.ToUpper(c.Domain),
			DefaultDomain: strings.ToUpper(c.Domain),
			AdminServer:   []string{dc.AddressWithoutPort()},
			KDC:           []string{net.JoinHostPort(dc.AddressWithoutPort(), "88")},
			KPasswdServer: []string{net.JoinHostPort(dc.AddressWithoutPort(), "464")},
			MasterKDC:     []string{dc.AddressWithoutPort()},
		},
		{
			Realm:         c.Domain,
			DefaultDomain: c.Domain,
			AdminServer:   []string{dc.AddressWithoutPort()},
			KDC:           []string{net.JoinHostPort(dc.AddressWithoutPort(), "88")},
			KPasswdServer: []string{net.JoinHostPort(dc.AddressWithoutPort(), "464")},
			MasterKDC:     []string{dc.AddressWithoutPort()},
		},
	}
	krbConf.DomainRealm = map[string]string{
		"." + c.Domain: strings.ToUpper(c.Domain),
		c.Domain:       strings.ToUpper(c.Domain),
	}

	return krbConf, nil
}

func splitUserIntoDomainAndUsername(user string) (domain string, username string) {
	switch {
	case strings.Contains(user, "@"):
		parts := strings.Split(user, "@")
		if len(parts) == 2 {
			return parts[1], parts[0]
		}

		return "", user
	case strings.Contains(user, `\`):
		parts := strings.Split(user, `\`)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}

		return "", user
	case strings.Contains(user, "/"):
		parts := strings.Split(user, "/")
		if len(parts) == 2 {
			return parts[0], parts[1]
		}

		return "", user
	default:
		return "", user
	}
}

func newKeytab() *keytab.Keytab {
	kt := &keytab.Keytab{}

	err := kt.Unmarshal([]byte{
		// header.
		0x05,                   // first-byte
		0x02,                   // version
		0x00, 0x00, 0x00, 0x00, // entry-length
	})
	if err != nil {
		panic(err.Error())
	}

	return kt
}

func addKeyToKeytab(kt *keytab.Keytab, username string, domain string, key string, aes bool, kvno uint32) error {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("decode AES key: %w", err)
	}

	var keyType int32

	switch len(keyBytes) {
	case 32:
		keyType = etypeID.AES256_CTS_HMAC_SHA1_96
	case 16:
		if aes {
			keyType = etypeID.AES128_CTS_HMAC_SHA1_96
		} else {
			keyType = etypeID.RC4_HMAC
		}
	default:
		return fmt.Errorf("invalid AES128/AES256 key")
	}

	tmp := &keytab.Keytab{}

	err = tmp.Unmarshal([]byte{
		// header
		0x05,                   // first-byte
		0x02,                   // version
		0x00, 0x00, 0x00, 0x11, // entry-length
		// principal
		0x00, 0x00, // num components
		0x00, 0x00, // realm length
		0x00, 0x00, 0x00, 0x00, // name type
		// key
		0x00, 0x00, 0x00, 0x00, // timestamp
		0x00,       // kvno8
		0x00, 0x00, // key type
		0x00, 0x00, // key length
	})
	if err != nil {
		return fmt.Errorf("invalid dummy data: %w", err)
	}

	e := tmp.Entries[0]

	krbCreds := credentials.New(username, domain)
	e.Principal.NumComponents = int16(len(krbCreds.CName().NameString))
	e.Principal.Components = krbCreds.CName().NameString
	e.Principal.Realm = strings.ToUpper(krbCreds.Realm())
	e.Principal.NameType = krbCreds.CName().NameType

	e.Timestamp = time.Now()
	e.KVNO8 = 0
	e.Key.KeyType = keyType
	e.Key.KeyValue = keyBytes
	e.KVNO = kvno

	kt.Entries = append(kt.Entries, e)

	return nil
}
