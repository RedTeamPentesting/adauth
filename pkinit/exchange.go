package pkinit

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/RedTeamPentesting/adauth/ccachetools"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/messages"
)

// DefaultKerberosRoundtripDeadline is the maximum time a roundtrip with the KDC
// can take before it is aborted. This deadline is for each KDC that is
// considered.
var DefaultKerberosRoundtripDeadline = 5 * time.Second

// Authenticate obtains a ticket granting ticket using PKINIT and returns it in
// a CCache which can be serialized using ccachetools.MarshalCCache.
func Authenticate(
	ctx context.Context, user string, domain string, cert *x509.Certificate, key *rsa.PrivateKey,
	krbConfig *config.Config, opts ...Option,
) (*credentials.CCache, error) {
	if user == "" {
		return nil, fmt.Errorf("username is empty")
	}

	if domain == "" {
		return nil, fmt.Errorf("domain is empty")
	}

	dialer, roundtripDeadline, err := processOptions(opts)
	if err != nil {
		return nil, err
	}

	asReq, dhClientNonce, err := NewASReq(user, domain, cert, key, key.D, krbConfig)
	if err != nil {
		return nil, fmt.Errorf("build ASReq: %w", err)
	}

	asRep, err := ASExchange(ctx, asReq, domain, krbConfig, dialer, roundtripDeadline)
	if err != nil {
		return nil, fmt.Errorf("exchange: %w", err)
	}

	_, err = Decrypt(&asRep, key.D, dhClientNonce)
	if err != nil {
		return nil, fmt.Errorf("decrypt ASRep: %w", err)
	}

	return ccachetools.NewCCacheFromASRep(asRep)
}

// ASExchange sends a ASReq to the KDC for the provided domain and returns the
// ASRep.
func ASExchange(
	ctx context.Context, asReq messages.ASReq, domain string, config *config.Config,
	dialer ContextDialer, roundtripDeadline time.Duration,
) (asRep messages.ASRep, err error) {
	asReqBytes, err := asReq.Marshal()
	if err != nil {
		return asRep, fmt.Errorf("marshal ASReq: %w", err)
	}

	asRepBytes, err := roundtrip(ctx, asReqBytes, config, domain, dialer, roundtripDeadline)
	if err != nil {
		return asRep, fmt.Errorf("roundtrip: %w", err)
	}

	err = asRep.Unmarshal(asRepBytes)
	if err != nil {
		return asRep, fmt.Errorf("unmarshal ASRep: %w", err)
	}

	return asRep, nil
}

// TGSExchange sends a TGSReq to the KDC for the provided domain and returns the
// TGSRep.
func TGSExchange(
	ctx context.Context, tgsReq messages.TGSReq, config *config.Config, domain string,
	dialer ContextDialer, roundtripDeadline time.Duration,
) (tgsRep messages.TGSRep, err error) {
	asReqBytes, err := tgsReq.Marshal()
	if err != nil {
		return tgsRep, fmt.Errorf("marshal ASReq: %w", err)
	}

	asRepBytes, err := roundtrip(ctx, asReqBytes, config, domain, dialer, roundtripDeadline)
	if err != nil {
		return tgsRep, fmt.Errorf("roundtrip: %w", err)
	}

	err = tgsRep.Unmarshal(asRepBytes)
	if err != nil {
		return tgsRep, fmt.Errorf("unmarshal ASRep: %w", err)
	}

	return tgsRep, nil
}

func roundtrip(
	ctx context.Context, request []byte, config *config.Config, domain string,
	dialer ContextDialer, roundtripDeadline time.Duration,
) (response []byte, err error) {
	_, kdcs, err := config.GetKDCs(domain, true)
	if err != nil {
		return nil, fmt.Errorf("get KDCs from config: %w", err)
	} else if len(kdcs) == 0 {
		return nil, fmt.Errorf("no KDCs found in config")
	}

	for i := 1; i <= len(kdcs); i++ {
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}

		response, err = roundtripForSingleKDC(ctx, request, kdcs[i], dialer, roundtripDeadline)
		if err == nil {
			return response, nil
		}
	}

	switch {
	case err != nil:
		return nil, err
	case ctx.Err() != nil:
		return nil, context.Cause(ctx)
	default:
		return nil, fmt.Errorf("unknown error")
	}
}

// ContextDialer is a context aware dialer such as net.Dialer or the SOCKS5
// dialer returned by proxy.SOCKS5.
type ContextDialer interface {
	DialContext(ctx context.Context, net string, addr string) (net.Conn, error)
}

func roundtripForSingleKDC(
	ctx context.Context, request []byte, address string,
	dialer ContextDialer, roundtripDeadline time.Duration,
) ([]byte, error) {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: roundtripDeadline}
	}

	ctx, cancel := context.WithTimeout(ctx, roundtripDeadline)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	var (
		responseChan = make(chan []byte)
		errChan      = make(chan error)
	)

	go func() {
		_ = conn.SetDeadline(time.Now().Add(roundtripDeadline))

		response, err := sendRecv(conn, request)

		_ = conn.Close()

		switch {
		case err != nil:
			errChan <- err
		default:
			responseChan <- response
		}
	}()

	select {
	case response := <-responseChan:
		return response, nil
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		conn.Close() //nolint:gosec

		return nil, context.Cause(ctx)
	}
}

func sendRecv(conn net.Conn, request []byte) ([]byte, error) {
	requestLengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(requestLengthBytes, uint32(len(request)))

	request = append(requestLengthBytes, request...) //nolint:makezero

	_, err := conn.Write(request)
	if err != nil {
		return nil, fmt.Errorf("error sending to KDC (%s): %w", conn.RemoteAddr().String(), err)
	}

	responseLengthBytes := make([]byte, 4)

	_, err = conn.Read(responseLengthBytes)
	if err != nil {
		return nil, fmt.Errorf("error reading response size header: %w", err)
	}

	responseLength := binary.BigEndian.Uint32(responseLengthBytes)

	responseBytes := make([]byte, responseLength)

	_, err = io.ReadFull(conn, responseBytes)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	if len(responseBytes) < 1 {
		return nil, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr().String())
	}

	return responseBytes, nil
}

// Option can be passed to a function to modify the default behavior.
type Option interface {
	isPKINITOption()
}

type option struct{}

func (option) isPKINITOption() {}

type dialerOption struct {
	option
	ContextDialer ContextDialer
}

// WithDialer can be used to set a custom dialer for communication with a DC.
func WithDialer(dialer ContextDialer) Option {
	return dialerOption{ContextDialer: dialer}
}

type deadlineOption struct {
	option
	Deadline time.Duration
}

// WithRoundtripDeadline can be used to set a deadline for a single
// request-response roundtrip with a single KDC.
func WithRoundtripDeadline(deadline time.Duration) Option {
	return deadlineOption{Deadline: deadline}
}

func processOptions(opts []Option) (dialer ContextDialer, roundtripDeadline time.Duration, err error) {
	roundtripDeadline = DefaultKerberosRoundtripDeadline

	for _, opt := range opts {
		switch o := opt.(type) {
		case dialerOption:
			dialer = o.ContextDialer
		case deadlineOption:
			roundtripDeadline = o.Deadline
		default:
			return nil, 0, fmt.Errorf("unknown option: %T", o)
		}
	}

	if dialer == nil {
		dialer = &net.Dialer{Timeout: roundtripDeadline}
	}

	return dialer, roundtripDeadline, nil
}
