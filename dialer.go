package adauth

import (
	"context"
	"net"
	"strings"

	"golang.org/x/net/proxy"
)

type Dialer interface {
	Dial(net string, addr string) (net.Conn, error)
}

type ContextDialer interface {
	DialContext(ctx context.Context, net string, addr string) (net.Conn, error)
	Dial(net string, addr string) (net.Conn, error)
}

type nopContextDialer func(string, string) (net.Conn, error)

func (f nopContextDialer) DialContext(ctx context.Context, net string, addr string) (net.Conn, error) {
	return f(net, addr)
}

func (f nopContextDialer) Dial(net string, addr string) (net.Conn, error) {
	return f(net, addr)
}

// AsContextDialer converts a Dialer into a ContextDialer that either uses the
// dialer's DialContext method if implemented or it uses a DialContext method
// that simply calls Dial ignoring the context.
func AsContextDialer(d Dialer) ContextDialer {
	ctxDialer, ok := d.(ContextDialer)
	if !ok {
		ctxDialer = nopContextDialer(d.Dial)
	}

	return ctxDialer
}

// SOCKS5Dialer returns a SOCKS5 dialer.
func SOCKS5Dialer(
	network string,
	address string,
	auth *proxy.Auth,
	forward *net.Dialer,
) ContextDialer {
	proxyDialer, err := proxy.SOCKS5(network, address, auth, forward)
	if err != nil {
		return nopContextDialer(func(s1, s2 string) (net.Conn, error) {
			return nil, err
		})
	}

	return AsContextDialer(proxyDialer)
}

// DialerWithSOCKS5ProxyIfSet returns a SOCKS5 dialer if socks5Server is not
// empty and it returns the forward dialer otherwise.
func DialerWithSOCKS5ProxyIfSet(socks5Server string, forward *net.Dialer) ContextDialer {
	if forward == nil {
		forward = &net.Dialer{}
	}

	if strings.TrimSpace(socks5Server) == "" {
		return AsContextDialer(forward)
	}

	return SOCKS5Dialer("tcp", socks5Server, nil, forward)
}
