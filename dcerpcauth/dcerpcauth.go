package dcerpcauth

import (
	"context"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/pkinit"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/smb2"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"

	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/etypeID"
)

// Options holds options that modify the behavior of the AuthenticationOptions
// function.
type Options struct {
	// SMBOptions holds options for the SMB dialer. This dialer is only used
	// with the named pipe transport. If SMBOptions is nil, encryption/sealing
	// will be enabled for the SMB dialer, specify an empty slice to disable
	// this default.
	SMBOptions []smb2.DialerOption

	// KerberosDialer is a custom dialer that is used to request Kerberos
	// tickets.
	KerberosDialer adauth.Dialer

	// Debug can be set to enable debug output, for example with
	// adauth.NewDebugFunc(...).
	Debug func(string, ...any)
}

func (opts *Options) debug(format string, a ...any) {
	if opts == nil || opts.Debug == nil {
		return
	}

	opts.Debug(format, a...)
}

// AuthenticationOptions returns dcerpc.Options for dcerpc.Dial or for
// constructing an DCERPC API client. It is possible to configure the SMB,
// PKINIT and debug behavior using the optional upstreamOptions argument.
func AuthenticationOptions(
	ctx context.Context, creds *adauth.Credential, target *adauth.Target,
	upstreamOptions *Options,
) (dcerpcOptions []dcerpc.Option, err error) {
	if upstreamOptions == nil {
		upstreamOptions = &Options{}
	}

	dcerpcCredentials, err := DCERPCCredentials(ctx, creds, upstreamOptions)
	if err != nil {
		return nil, err
	}

	dcerpcOptions = append(dcerpcOptions, dcerpc.WithMechanism(ssp.SPNEGO))

	switch {
	case target.UseKerberos || creds.ClientCert != nil:
		spn, err := target.SPN(ctx)
		if err != nil {
			return nil, fmt.Errorf("build SPN: %w", err)
		}

		upstreamOptions.debug("Using Kerberos with SPN %q", spn)

		krbConf, err := creds.KerberosConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("generate Kerberos config: %w", err)
		}

		smbOptions := upstreamOptions.SMBOptions
		if smbOptions == nil {
			smbOptions = append(smbOptions, smb2.WithSeal())
		}

		smbOptions = append(smbOptions, smb2.WithSecurity(
			gssapi.WithTargetName(spn),
			gssapi.WithCredential(dcerpcCredentials),
			gssapi.WithMechanismFactory(ssp.KRB5, &krb5.Config{
				KRB5Config:      krbConf,
				CCachePath:      creds.CCache,
				DisablePAFXFAST: true,
				DCEStyle:        true,
				KDCDialer:       upstreamOptions.KerberosDialer,
			}),
		))

		dcerpcOptions = append(dcerpcOptions,
			dcerpc.WithTargetName(spn),
			dcerpc.WithMechanism(ssp.KRB5),
			dcerpc.WithSecurityConfig(&krb5.Config{
				KRB5Config:      krbConf,
				CCachePath:      creds.CCache,
				DisablePAFXFAST: true,
				DCEStyle:        true,
				KDCDialer:       upstreamOptions.KerberosDialer,
			}),
			dcerpc.WithSMBDialer(smb2.NewDialer(smbOptions...)),
		)
	default:
		upstreamOptions.debug("Using NTLM")

		dcerpcOptions = append(dcerpcOptions,
			dcerpc.WithMechanism(ssp.NTLM),
		)

		spn, err := target.SPN(ctx)
		if err == nil {
			dcerpcOptions = append(dcerpcOptions, dcerpc.WithTargetName(spn))
		}
	}

	dcerpcOptions = append(dcerpcOptions, dcerpc.WithCredentials(dcerpcCredentials))

	return dcerpcOptions, nil
}

func DCERPCCredentials(ctx context.Context, creds *adauth.Credential, options *Options) (credential.Credential, error) {
	switch {
	case creds.Password != "":
		options.debug("Authenticating with password")

		return credential.NewFromPassword(creds.LogonNameWithUpperCaseDomain(), creds.Password), nil
	case creds.AESKey != "":
		options.debug("Authenticating with AES key")

		keyBytes, err := hex.DecodeString(creds.AESKey)
		if err != nil {
			return nil, fmt.Errorf("decode hex key: %w", err)
		}

		var keyType int

		switch len(keyBytes) {
		case 32:
			keyType = int(etypeID.AES256_CTS_HMAC_SHA1_96)
		case 16:
			keyType = int(etypeID.AES128_CTS_HMAC_SHA1_96)
		default:
			return nil, fmt.Errorf("invalid AES128/AES256 key: key size is %d bytes", len(keyBytes))
		}

		return credential.NewFromEncryptionKeyBytes(creds.LogonNameWithUpperCaseDomain(), keyType, keyBytes), nil
	case creds.NTHash != "":
		options.debug("Authenticating with NT hash")

		return credential.NewFromNTHash(creds.LogonNameWithUpperCaseDomain(), creds.NTHash), nil
	case creds.PasswordIsEmtpyString:
		options.debug("Authenticating with empty password")

		return credential.NewFromPassword(strings.ToUpper(creds.Domain)+`\`+creds.Username, ""), nil
	case creds.ClientCert != nil:
		options.debug("Authenticating with client certificate (PKINIT)")

		krbConf, err := creds.KerberosConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("generate kerberos config: %w", err)
		}

		dialer := options.KerberosDialer
		if dialer == nil {
			dialer = &net.Dialer{Timeout: pkinit.DefaultKerberosRoundtripDeadline}
		}

		rsaKey, ok := creds.ClientCertKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("cannot use %T because PKINIT requires an RSA key", creds.ClientCertKey)
		}

		ccache, err := pkinit.Authenticate(ctx, creds.Username, strings.ToUpper(creds.Domain),
			creds.ClientCert, rsaKey, krbConf, pkinit.WithDialer(adauth.AsContextDialer(dialer)))
		if err != nil {
			return nil, fmt.Errorf("PKINIT: %w", err)
		}

		return credential.NewFromCCache(creds.LogonNameWithUpperCaseDomain(), ccache), nil
	case creds.CCache != "":
		options.debug("Authenticating with ccache")

		ccache, err := credentials.LoadCCache(creds.CCache)
		if err != nil {
			return nil, fmt.Errorf("load CCache: %w", err)
		}

		return credential.NewFromCCache(creds.LogonNameWithUpperCaseDomain(), ccache), nil
	default:
		return nil, fmt.Errorf("no credentials available")
	}
}
