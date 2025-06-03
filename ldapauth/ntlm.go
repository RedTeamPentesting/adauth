package ldapauth

import (
	"crypto/x509"
	"fmt"

	"github.com/Azure/go-ntlmssp"
	"github.com/go-ldap/ldap/v3"
	"github.com/vadimi/go-ntlm/ntlm"
)

type ntlmNegotiator struct {
	cert               *x509.Certificate
	overrideTargetName string
}

var _ ldap.NTLMNegotiator = &ntlmNegotiator{}

func ntlmNegotiatorWithChannelBinding(cert *x509.Certificate, domain string) ldap.NTLMNegotiator {
	return &ntlmNegotiator{cert: cert, overrideTargetName: domain}
}

func ntlmNegotiatorForDomain(domain string) ldap.NTLMNegotiator {
	return &ntlmNegotiator{overrideTargetName: domain}
}

func (n *ntlmNegotiator) Negotiate(domain string, worktation string) ([]byte, error) {
	return ntlmssp.NewNegotiateMessage(domain, worktation)
}

func (n *ntlmNegotiator) ChallengeResponse(challenge []byte, username string, hash string) ([]byte, error) {
	if n.cert == nil && n.overrideTargetName == "" {
		// no cert means no channel binding, so Azure/ntlmssp can handle
		// authentication alone.
		return ntlmssp.ProcessChallengeWithHash(challenge, username, hash)
	}

	// The authenticate message needs to include a channel binding hash, but the
	// Azure/ntlmssp library does not support channel binding and offers no API
	// to retrofit it. The only way to make it work is too parse the challenge,
	// add the channel bindings to the challenge's TargetInfo field which will
	// then be included in the authenticate message. Unfortunately we need
	// another NTLM library because message marshalling and unmarshalling is
	// also not exposed in Azure/ntlmssp.
	cm, err := ntlm.ParseChallengeMessage(challenge)
	if err != nil {
		return nil, fmt.Errorf("parse NTLM challenge before injecting channel binding AVPair: %w", err)
	}

	if n.cert != nil {
		// drop end-of-list marker if present because we want to add another entry
		if len(cm.TargetInfo.List) > 0 && cm.TargetInfo.List[len(cm.TargetInfo.List)-1].AvId == ntlm.MsvAvEOL {
			cm.TargetInfo.List = cm.TargetInfo.List[:len(cm.TargetInfo.List)-1]
		}

		// add channel bindings
		cm.TargetInfo.AddAvPair(ntlm.MsvChannelBindings, ChannelBindingHash(n.cert))
		cm.TargetInfo.AddAvPair(ntlm.MsvAvEOL, nil)

		cm.TargetInfoPayloadStruct, err = ntlm.CreateBytePayload(cm.TargetInfo.Bytes())
		if err != nil {
			return nil, fmt.Errorf("marshal AVPairs with injected channel binding AVPair: %w", err)
		}
	}

	// Authenticate with the domain name that was specified, not the domain that
	// the server advertises. This grants compatibility with the LDAP SOCKS
	// feature of ntlmrelayx.py which is sensitive to the exact domain name (DNS
	// vs NetBIOS name).
	if n.overrideTargetName != "" && n.overrideTargetName != "." {
		cm.TargetName, err = ntlm.CreateStringPayload(n.overrideTargetName)
		if err != nil {
			return nil, fmt.Errorf("override target name: create string payload: %w", err)
		}
	}

	// make sure that the server cannot make cm.Bytes() panic by omitting the
	// version.
	if cm.Version == nil {
		cm.Version = &ntlm.VersionStruct{}
	}

	return ntlmssp.ProcessChallengeWithHash(cm.Bytes(), username, hash)
}
