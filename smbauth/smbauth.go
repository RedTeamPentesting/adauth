package smbauth

import (
	"context"
	"fmt"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/dcerpcauth"

	"github.com/oiweiwei/go-smb2.fork"

	msrpcSMB2 "github.com/oiweiwei/go-msrpc/smb2"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"
)

// Options holds options that modify the behavior of the Dialer function.
type Options struct {
	// SMBOptions holds options for the SMB dialer. If SMBOptions is nil,
	// encryption/sealing will be enabled. Specify an empty slice to disable
	// this default.
	SMBOptions []msrpcSMB2.DialerOption

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

// Dialer returns an SMB dialer which is prepared for authentication with the
// given credentials. The dialer can be further customized with
// options.SMBDialerOptions.
func Dialer(
	ctx context.Context, creds *adauth.Credential, target *adauth.Target, options *Options,
) (*smb2.Dialer, error) {
	smbCreds, err := dcerpcauth.DCERPCCredentials(ctx, creds, &dcerpcauth.Options{
		Debug:          options.debug,
		KerberosDialer: options.KerberosDialer,
	})
	if err != nil {
		return nil, err
	}

	dialerOptions := options.SMBOptions
	if dialerOptions == nil {
		dialerOptions = append(dialerOptions, msrpcSMB2.WithSeal())
	}

	switch {
	case target.UseKerberos || creds.ClientCert != nil:
		spn, err := target.SPN(ctx)
		if err != nil {
			return nil, fmt.Errorf("build SPN: %w", err)
		}

		options.debug("Using Kerberos with SPN %q", spn)

		krbConf, err := creds.KerberosConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("generate Kerberos config: %w", err)
		}

		dialerOptions = append(dialerOptions, msrpcSMB2.WithSecurity(
			gssapi.WithTargetName(spn),
			gssapi.WithCredential(smbCreds),
			gssapi.WithMechanismFactory(ssp.KRB5, &krb5.Config{
				KRB5Config:      krbConf,
				CCachePath:      creds.CCache,
				DisablePAFXFAST: true,
				KDCDialer:       options.KerberosDialer,
			}),
		))

		return msrpcSMB2.NewDialer(dialerOptions...), nil
	default:
		options.debug("Using NTLM")

		secOptions := []gssapi.ContextOption{
			gssapi.WithCredential(smbCreds),
			gssapi.WithMechanismFactory(ssp.NTLM),
		}

		spn, err := target.SPN(ctx)
		if err == nil {
			secOptions = append(secOptions, gssapi.WithTargetName(spn))
		}

		dialerOptions = append(dialerOptions, msrpcSMB2.WithSecurity(secOptions...))

		return msrpcSMB2.NewDialer(dialerOptions...), nil
	}
}
