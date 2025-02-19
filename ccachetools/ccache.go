package ccachetools

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// NewCCache constructs an in-memory CCache.
func NewCCache(
	ticket messages.Ticket, key types.EncryptionKey,
	serverName types.PrincipalName, clientName types.PrincipalName, clientRealm string,
	authTime time.Time, startTime time.Time, endTime time.Time, renewTill time.Time,
) (*credentials.CCache, error) {
	ticketBytes, err := ticket.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal ticket for ccache: %w", err)
	}

	entry := &credentials.Credential{
		Key:       key,
		AuthTime:  authTime,
		StartTime: startTime,
		EndTime:   endTime,
		RenewTill: renewTill,
		Ticket:    ticketBytes,
	}

	entry.Client.PrincipalName = clientName
	entry.Client.Realm = clientRealm
	entry.Server.PrincipalName = serverName
	entry.Server.Realm = clientRealm

	ccache := &credentials.CCache{
		Credentials: []*credentials.Credential{entry},
	}

	ccache.DefaultPrincipal.PrincipalName = clientName
	ccache.DefaultPrincipal.Realm = strings.ToUpper(clientRealm)

	return ccache, nil
}

// NewCCacheFromASRep constructs an in-memory CCache based on the ticket and key
// in the provided Kerberos ASRep message. The ASRep message must already be
// decrypted. The CCache will contain only this ticket and the ticket user will
// be set as the default principal of the CCache.
func NewCCacheFromASRep(asRep messages.ASRep) (*credentials.CCache, error) {
	if len(asRep.DecryptedEncPart.Key.KeyValue) == 0 {
		return nil, fmt.Errorf("ASRep key was not decrypted")
	}

	return NewCCache(
		asRep.Ticket, asRep.DecryptedEncPart.Key,
		asRep.DecryptedEncPart.SName, asRep.CName, asRep.CRealm,
		asRep.DecryptedEncPart.AuthTime, asRep.DecryptedEncPart.StartTime,
		asRep.DecryptedEncPart.EndTime, asRep.DecryptedEncPart.RenewTill)
}

// NewCCacheFromTGSRep constructs an in-memory CCache based on the ticket and
// key in the provided Kerberos TGSRep message. The TGSRep message must already
// be decrypted. The CCache will contain only this ticket and the ticket user
// will be set as the default principal of the CCache.
func NewCCacheFromTGSRep(tgsRep messages.TGSRep) (*credentials.CCache, error) {
	if len(tgsRep.DecryptedEncPart.Key.KeyValue) == 0 {
		return nil, fmt.Errorf("TGSRep key was not decrypted")
	}

	return NewCCache(
		tgsRep.Ticket, tgsRep.DecryptedEncPart.Key,
		tgsRep.DecryptedEncPart.SName, tgsRep.CName, tgsRep.CRealm,
		tgsRep.DecryptedEncPart.AuthTime, tgsRep.DecryptedEncPart.StartTime,
		tgsRep.DecryptedEncPart.EndTime, tgsRep.DecryptedEncPart.RenewTill)
}

// MarshalCCache returns the byte representation of the provided CCache such
// that it can be saved on-disk.
func MarshalCCache(ccache *credentials.CCache) ([]byte, error) {
	switch ccache.Version {
	case 0, 1, 2, 3, 4:
	default:
		return nil, fmt.Errorf("unsupported CCache version: %d", ccache.Version)
	}

	version := ccache.Version
	if version == 0 {
		version = 4
	}

	var bo binary.AppendByteOrder = binary.BigEndian

	if version == 1 || version == 2 {
		bo = binary.LittleEndian
	}

	buf := []byte{5, version}

	// header
	if version == 4 {
		buf = bo.AppendUint16(buf, 0)
	}

	// default principal
	buf = append(buf, principalBytes(bo, version,
		ccache.DefaultPrincipal.PrincipalName, ccache.DefaultPrincipal.Realm)...)

	// credentials
	for _, cred := range ccache.Credentials {
		buf = append(buf, credentialBytes(bo, version, cred)...)
	}

	return buf, nil
}

func principalBytes(bo binary.AppendByteOrder, v uint8, p types.PrincipalName, realm string) (res []byte) {
	if v != 1 {
		res = bo.AppendUint32(res, uint32(p.NameType))
	}

	nCompontents := len(p.NameString)
	if v == 1 {
		nCompontents--
	}

	res = bo.AppendUint32(res, uint32(nCompontents))
	res = bo.AppendUint32(res, uint32(len(realm)))

	res = append(res, []byte(realm)...)

	for _, part := range p.NameString {
		res = bo.AppendUint32(res, uint32(len(part)))
		res = append(res, []byte(part)...)
	}

	return res
}

func credentialBytes(bo binary.AppendByteOrder, v uint8, cred *credentials.Credential) (res []byte) {
	res = append(res, principalBytes(bo, v, cred.Client.PrincipalName, cred.Client.Realm)...)
	res = append(res, principalBytes(bo, v, cred.Server.PrincipalName, cred.Server.Realm)...)

	res = bo.AppendUint16(res, uint16(cred.Key.KeyType))
	res = bo.AppendUint32(res, uint32(len(cred.Key.KeyValue)))
	res = append(res, cred.Key.KeyValue...)

	res = bo.AppendUint32(res, uint32(cred.AuthTime.Unix()))
	res = bo.AppendUint32(res, uint32(cred.StartTime.Unix()))
	res = bo.AppendUint32(res, uint32(cred.EndTime.Unix()))
	res = bo.AppendUint32(res, uint32(cred.RenewTill.Unix()))

	if cred.IsSKey {
		res = append(res, 1)
	} else {
		res = append(res, 0)
	}

	flags := cred.TicketFlags.Bytes
	if len(flags) == 0 {
		flags = make([]byte, 4)
	}

	res = append(res, flags...)

	res = bo.AppendUint32(res, uint32(len(cred.Addresses)))

	for _, addr := range cred.Addresses {
		res = bo.AppendUint16(res, uint16(addr.AddrType))
		res = bo.AppendUint32(res, uint32(len(addr.Address)))
		res = append(res, addr.Address...)
	}

	res = bo.AppendUint32(res, uint32(len(cred.AuthData)))

	for _, data := range cred.AuthData {
		res = bo.AppendUint16(res, uint16(data.ADType))
		res = bo.AppendUint32(res, uint32(len(data.ADData)))
		res = append(res, data.ADData...)
	}

	res = bo.AppendUint32(res, uint32(len(cred.Ticket)))
	res = append(res, cred.Ticket...)

	res = bo.AppendUint32(res, uint32(len(cred.SecondTicket)))
	res = append(res, cred.SecondTicket...)

	return res
}
