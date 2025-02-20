package dcerpcauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/pkinit"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/smb2"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"
)

// Options holds options that modify the behavior of the AuthenticationOptions
// function.
type Options struct {
	// SMBOptions holds options for the SMB dialer. This dialer is only used
	// with the named pipe transport. If SMBOptions is nil, sealing will be
	// enabled for the smb dialer, specify an empty slice to disable this
	// default.
	SMBOptions []smb2.DialerOption
	// PKINITOptions can be used to modify the Kerberos PKINIT behavior.
	PKINITOptions []pkinit.Option
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

		keyTab, err := creds.Keytab()
		if err != nil {
			return nil, fmt.Errorf("create keytab: %w", err)
		}

		return &keytabCredentials{username: creds.Username, domain: creds.Domain, keytab: keyTab}, nil
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

		ccache, err := pkinit.Authenticate(ctx, creds.Username, strings.ToUpper(creds.Domain),
			creds.ClientCert, creds.ClientCertKey, krbConf, options.PKINITOptions...)
		if err != nil {
			return nil, fmt.Errorf("PKINIT: %w", err)
		}

		return credential.NewFromCCache(creds.LogonNameWithUpperCaseDomain(), ccache), nil
	case creds.CCache != "":
		options.debug("Authenticating with ccache")

		return credential.NewFromPassword(creds.LogonNameWithUpperCaseDomain(), ""), nil
	default:
		return nil, fmt.Errorf("no credentials available")
	}
}

type keytabCredentials struct {
	keytab   *keytab.Keytab
	username string
	domain   string
}

var _ credential.Keytab = &keytabCredentials{}

func (ktc *keytabCredentials) DomainName() string {
	return strings.ToUpper(ktc.domain)
}

func (ctc *keytabCredentials) Workstation() string {
	return ""
}

func (ctc *keytabCredentials) UserName() string {
	return ctc.username
}

func (ctc *keytabCredentials) Keytab() *keytab.Keytab {
	return ctc.keytab
}
