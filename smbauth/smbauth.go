package smbauth

import (
  "context"
  "fmt"
  "strings"

  "github.com/RedTeamPentesting/adauth"
  "github.com/RedTeamPentesting/adauth/pkinit"

  "github.com/jcmturner/gokrb5/v8/keytab"
  "github.com/oiweiwei/go-msrpc/smb2"
  "github.com/oiweiwei/go-msrpc/ssp"
  "github.com/oiweiwei/go-msrpc/ssp/credential"
  "github.com/oiweiwei/go-msrpc/ssp/gssapi"
  "github.com/oiweiwei/go-msrpc/ssp/krb5"
)

// Options holds options that modify the behavior of the AuthenticationOptions
// function.
type Options struct {
  // SMBOptions holds options for the SMB dialer. If SMBOptions is nil,
  // sealing will be enabled for the smb dialer, specify an empty slice
  // to disable this default.
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

// AuthenticationOptions returns the security context options for
// smb2.WithSecurity. It is possible to configure the SMB, PKINIT
// and debug behavior using the optional upstreamOptions argument.
func AuthenticationOptions(
  ctx context.Context, creds *adauth.Credential, target *adauth.Target,
  upstreamOptions *Options,
) (dialOptions []smb2.DialerOption, secOptions []gssapi.ContextOption, err error) {

  if dialOptions = upstreamOptions.SMBOptions; dialOptions == nil {
    dialOptions = []smb2.DialerOption{smb2.WithSeal()}
  }

  smbCredentials, err := SMBCredentials(ctx, creds, upstreamOptions)
  if err != nil {
    return nil, nil, err
  }

  switch {
  case target.UseKerberos || creds.ClientCert != nil:
    spn, err := target.SPN(ctx)
    if err != nil {
      return nil, nil, fmt.Errorf("build SPN: %w", err)
    }
    upstreamOptions.debug("Using Kerberos with SPN %q", spn)

    krbConf, err := creds.KerberosConfig(ctx)
    if err != nil {
      return nil, nil, fmt.Errorf("generate Kerberos config: %w", err)
    }

    secOptions = append(secOptions,
      gssapi.WithTargetName(spn),
      gssapi.WithCredential(smbCredentials),
      gssapi.WithMechanismFactory(ssp.KRB5, &krb5.Config{
        KRB5Config:      krbConf,
        CCachePath:      creds.CCache,
        DisablePAFXFAST: true,
        DCEStyle:        true,
      }),
    )
  default:
    upstreamOptions.debug("Using NTLM")

    secOptions = append(secOptions,
      gssapi.WithCredential(smbCredentials),
      gssapi.WithMechanismFactory(ssp.NTLM),
    )
    // Try fetching SPN
    if spn, err := target.SPN(ctx); err == nil {
      secOptions = append(secOptions, gssapi.WithTargetName(spn))
    }
  }
  return
}

func SMBCredentials(ctx context.Context, creds *adauth.Credential, options *Options) (credential.Credential, error) {
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

var _ credential.KeytabV8 = &keytabCredentials{}

func (ktc *keytabCredentials) DomainName() string {
  return strings.ToUpper(ktc.domain)
}

func (ktc *keytabCredentials) Workstation() string {
  return ""
}

func (ktc *keytabCredentials) UserName() string {
  return ktc.username
}

func (ktc *keytabCredentials) Keytab() *keytab.Keytab {
  return ktc.keytab
}
