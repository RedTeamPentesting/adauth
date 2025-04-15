package main

import (
	"context"
	"fmt"
	"os"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/ldapauth"
	"github.com/spf13/pflag"
)

func run() error {
	var (
		debug       bool
		socksServer = os.Getenv("SOCKS5_SERVER")
		authOpts    = &adauth.Options{
			Debug: adauth.NewDebugFunc(&debug, os.Stderr, true),
		}
		ldapOpts = &ldapauth.Options{
			Debug: adauth.NewDebugFunc(&debug, os.Stderr, true),
		}
	)

	pflag.CommandLine.BoolVar(&debug, "debug", false, "Enable debug output")
	pflag.CommandLine.StringVar(&socksServer, "socks", socksServer, "SOCKS5 proxy server")
	authOpts.RegisterFlags(pflag.CommandLine)
	ldapOpts.RegisterFlags(pflag.CommandLine)
	pflag.Parse()

	ldapOpts.SetDialer(adauth.DialerWithSOCKS5ProxyIfSet(socksServer, nil))

	conn, err := ldapauth.Connect(context.Background(), authOpts, ldapOpts)
	if err != nil {
		return fmt.Errorf("%s connect: %w", ldapOpts.Scheme, err)
	}

	defer conn.Close() //nolint:errcheck

	res, err := conn.WhoAmI(nil)
	if err != nil {
		return fmt.Errorf("whoami: %w", err)
	}

	fmt.Println("whoami:", res.AuthzID)

	return nil
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)

		os.Exit(1)
	}
}
