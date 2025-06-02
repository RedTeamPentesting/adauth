package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/smbauth"
	"github.com/spf13/pflag"
)

func run() error {
	var (
		debug       bool
		socksServer = os.Getenv("SOCKS5_SERVER")
		authOpts    = &adauth.Options{
			Debug: adauth.NewDebugFunc(&debug, os.Stderr, true),
		}
		smbauthOpts = &smbauth.Options{
			Debug: authOpts.Debug,
		}
	)

	pflag.CommandLine.BoolVar(&debug, "debug", false, "Enable debug output")
	pflag.CommandLine.StringVar(&socksServer, "socks", socksServer, "SOCKS5 proxy server")
	authOpts.RegisterFlags(pflag.CommandLine)
	pflag.Parse()

	if len(pflag.Args()) != 1 {
		return fmt.Errorf("usage: %s [options] <target>", binaryName())
	}

	creds, target, err := authOpts.WithTarget(context.Background(), "host", pflag.Arg(0))
	if err != nil {
		return err
	}

	if target.Port == "" {
		target.Port = "445"
	}

	ctx := context.Background()

	smbauthOpts.KerberosDialer = adauth.DialerWithSOCKS5ProxyIfSet(socksServer, nil)

	smbDialer, err := smbauth.Dialer(ctx, creds, target, smbauthOpts)
	if err != nil {
		return fmt.Errorf("setup SMB authentication: %w", err)
	}

	conn, err := adauth.DialerWithSOCKS5ProxyIfSet(socksServer, nil).DialContext(ctx, "tcp", target.Address())
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	defer conn.Close()

	sess, err := smbDialer.DialContext(ctx, conn)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	defer sess.Logoff()

	shares, err := sess.ListSharenames()
	if err != nil {
		return fmt.Errorf("list share names: %w", err)
	}

	if len(shares) == 0 {
		fmt.Println("No shares available")

		return nil
	}

	fmt.Println("Shares:")

	for _, share := range shares {
		fmt.Printf(" - %s\n", share)
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

	return "smb"
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)

		os.Exit(1)
	}
}
