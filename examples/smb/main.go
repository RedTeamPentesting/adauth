package main

import (
  "context"
  "fmt"
  "github.com/RedTeamPentesting/adauth/smbauth"
  "github.com/oiweiwei/go-msrpc/smb2"
  "github.com/oiweiwei/go-msrpc/ssp"
  "net"
  "os"
  "path/filepath"

  "github.com/RedTeamPentesting/adauth"
  "github.com/oiweiwei/go-msrpc/ssp/gssapi"
  "github.com/spf13/pflag"
)

var (
  debug    bool
  authOpts = &adauth.Options{
    Debug: adauth.NewDebugFunc(&debug, os.Stderr, true),
  }
)

func init() {
  pflag.CommandLine.BoolVar(&debug, "debug", false, "Enable debug output")
  authOpts.RegisterFlags(pflag.CommandLine)
  gssapi.AddMechanism(ssp.SPNEGO)
  gssapi.AddMechanism(ssp.NTLM)
}

func run() error {
  pflag.Parse()

  if len(pflag.Args()) != 1 {
    return fmt.Errorf("usage: %s <target> [--debug]", binaryName())
  }

  creds, target, err := authOpts.WithTarget(context.Background(), "host", pflag.Arg(0))
  if err != nil {
    return err
  }

  ctx := gssapi.NewSecurityContext(context.Background())

  smbOpts, secOpts, err := smbauth.AuthenticationOptions(ctx, creds, target, &smbauth.Options{})
  if err != nil {
    return err
  }

  // Create go-smb2 Dialer
  dialer := smb2.NewDialer(append(smbOpts, smb2.WithSecurity(secOpts...))...)

  conn, err := net.Dial("tcp", net.JoinHostPort(target.AddressWithoutPort(), "445"))
  if err != nil {
    return err
  }
  defer conn.Close()

  sess, err := dialer.Dial(conn)
  if err != nil {
    return err
  }
  defer sess.Logoff()

  names, err := sess.ListSharenames()
  if err != nil {
    return err
  }

  for _, name := range names {
    fmt.Println(name)
  }
  return nil
}

func binaryName() string {
  executable, err := os.Executable()
  if err == nil {
    return filepath.Base(executable)
  }

  if len(os.Args) > 0 {
    return filepath.Base(os.Args[0])
  }

  return "list-shares"
}

func main() {
  err := run()
  if err != nil {
    fmt.Fprintf(os.Stderr, "Error: %v\n", err)

    os.Exit(1)
  }
}
