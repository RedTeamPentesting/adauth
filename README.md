<p align="center">
  <h1 align="center"><b>adauth</b></h1>
  <p align="center"><i>Active Directory Authentication Library</i></p>
  <p align="center">
    <a href="https://github.com/RedTeamPentesting/adauth/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/RedTeamPentesting/adauth.svg?style=for-the-badge"></a>
    <a href="https://pkg.go.dev/github.com/RedTeamPentesting/adauth"><img alt="Go Doc" src="https://img.shields.io/badge/godoc-reference-blue.svg?style=for-the-badge"></a>
    <a href="https://github.com/RedTeamPentesting/adauth/actions?workflow=Check"><img alt="GitHub Action: Check" src="https://img.shields.io/github/actions/workflow/status/RedTeamPentesting/adauth/check.yml?branch=main&style=for-the-badge"></a>
    <a href="/LICENSE"><img alt="Software License" src="https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge"></a>
    <a href="https://goreportcard.com/report/github.com/RedTeamPentesting/adauth"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/RedTeamPentesting/adauth?style=for-the-badge"></a>
  </p>
</p>


**Warning: The API of this library is not yet stable. Expect breaking changes.**

`adauth` is a Go library for active directory authentication. It can be used to
quickly set up authentication options:

```go
var (
    ctx = context.Background()
    authOpts = &adauth.Options{}
)

authOpts.RegisterFlags(pflag.CommandLine)
pflag.Parse()
//     --aes-key hex key       Kerberos AES hex key
//     --ccache file           Kerberos CCache file name (defaults to $KRB5CCNAME, currently unset)
//     --dc string             Domain controller
// -k, --kerberos              Use Kerberos authentication
// -H, --nt-hash hash          NT hash ('NT', ':NT' or 'LM:NT')
// -p, --password string       Password
//     --pfx file              Client certificate and private key as PFX file
//     --pfx-password string   Password for PFX file
// -u, --user user@domain      Username ('user@domain', 'domain\user', 'domain/user' or 'user')

// Credentials for an arbitrary target:
creds, target, err := authOpts.WithTarget(ctx, "smb", pflag.Arg(0))
if err != nil { /* error handling */ }


// Only credentials are needed, no specific target:
creds, err := authOpts.NoTarget()
if err != nil { /* error handling */ }

// Credentials to authenticate to the corresponding DC:
creds, dc, err := authOpts.WithDCTarget(ctx, "ldap")
if err != nil { /* error handling */ }
```

It deduces as much information from the parameters as possible. For example,
Kerberos authentication is possible even when specifying the target via IP
address if reverse lookups are possible. Similarly, the domain can be omitted
when the target hostname contains the domain.

The library also contains helper packages for LDAP, SMB and DCERPC, a Kerebros
PKINIT implementation as well as helpers for creating and writing CCache files
(see examples).

## Features

* Kerberos:
  * PKINIT
  * UnPAC-the-Hash
  * Pass-the-Hash (RC4/NT or AES key)
  * CCache (containing TGT or ST)
  * SOCKS5 support
* NTLM:
  * Pass-the-Hash
* LDAP:
  * Kerberos, NTLM, Simple Bind
  * mTLS Authentication / Pass-the-Certificate (LDAPS or LDAP+StartTLS)
  * Channel Binding (Kerberos and NTLM)
  * SOCKS5 support
* SMB:
  * Kerberos, NTLM
  * Signing and Sealing
  * SOCKS5 support
* DCERPC:
  * Kerberos, NTLM
  * Raw endpoits (with port mapping)
  * Named pipes (SMB)
  * Signing and Sealing
  * SOCKS5 support

## Caveats

**LDAP:**

The LDAP helper package does not support authentication using RC4 service
tickets from `ccache`, since Windows returns unsupported GSSAPI wrap tokens
during the SASL handshake when presented with an RC4 service ticket (see
[github.com/jcmturner/gokrb5/pull/498](https://github.com/jcmturner/gokrb5/pull/498)).

However, it should still be possible to request an AES256 service ticket
instead, even when an NT hash was used for pre-authentication . Unfortunately,
[impacket](https://github.com/fortra/impacket) always requests RC4 tickets. This
behavior can be changed by adding
`int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),` as the first
element of [this
list](https://github.com/fortra/impacket/blob/af91d617c382e1eb132506159debcbc10da7a567/impacket/krb5/kerberosv5.py#L447-L450).

The LDAP library does not (yet) support LDAP signing, but it supports channel
binding for LDAPS and LDAP+StartTLS which is typically sufficient as a
workaround unless the server lacks a TLS certificate.

