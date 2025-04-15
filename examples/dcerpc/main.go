package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/dcerpcauth"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
	"github.com/spf13/pflag"
)

func run() error {
	var (
		debug       bool
		socksServer = os.Getenv("SOCKS5_SERVER")
		authOpts    = &adauth.Options{
			Debug: adauth.NewDebugFunc(&debug, os.Stderr, true),
		}
		dcerpcauthOpts = &dcerpcauth.Options{
			Debug: authOpts.Debug,
		}
		namedPipe bool
	)

	pflag.CommandLine.BoolVar(&debug, "debug", false, "Enable debug output")
	pflag.CommandLine.StringVar(&socksServer, "socks", socksServer, "SOCKS5 proxy server")
	pflag.CommandLine.BoolVar(&namedPipe, "named-pipe", false, "Use named pipe (SMB) as transport")
	authOpts.RegisterFlags(pflag.CommandLine)
	pflag.Parse()

	if len(pflag.Args()) != 1 {
		return fmt.Errorf("usage: %s [options] <target>", binaryName())
	}

	dcerpcauthOpts.KerberosDialer = adauth.DialerWithSOCKS5ProxyIfSet(socksServer, nil)

	creds, target, err := authOpts.WithTarget(context.Background(), "host", pflag.Arg(0))
	if err != nil {
		return err
	}

	ctx := context.Background()

	dcerpcOpts, err := dcerpcauth.AuthenticationOptions(ctx, creds, target, dcerpcauthOpts)
	if err != nil {
		return err
	}

	dcerpcOpts = append(dcerpcOpts,
		epm.EndpointMapper(ctx,
			net.JoinHostPort(target.AddressWithoutPort(), "135"),
			dcerpc.WithInsecure(),
		),
		dcerpc.WithDialer(adauth.DialerWithSOCKS5ProxyIfSet(socksServer, nil)),
	)

	proto := "ncacn_ip_tcp:"
	if namedPipe {
		proto = "ncacn_np:"
	}

	conn, err := dcerpc.Dial(ctx, proto+target.Address(), dcerpcOpts...)
	if err != nil {
		return fmt.Errorf("dial DCERPC: %w", err)
	}

	defer conn.Close(ctx) //nolint:errcheck

	samrClient, err := samr.NewSamrClient(ctx, conn, dcerpc.WithSeal())
	if err != nil {
		return fmt.Errorf("create SAMR client: %w", err)
	}

	connectResponse, err := samrClient.Connect(ctx, &samr.ConnectRequest{DesiredAccess: 0x02000000})
	if err != nil {
		return fmt.Errorf("SAMR connect: %w", err)
	}

	lookupDomainResponse, err := samrClient.LookupDomainInSAMServer(ctx, &samr.LookupDomainInSAMServerRequest{
		Server: connectResponse.Server,
		Name: &dtyp.UnicodeString{
			Buffer: creds.Domain,
		},
	})
	if err != nil {
		return fmt.Errorf("SAMR lookup domain %q: %w", creds.Domain, err)
	}

	fmt.Println("Domain SID:", lookupDomainResponse.DomainID)

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

	return "msrpc"
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)

		os.Exit(1)
	}
}
