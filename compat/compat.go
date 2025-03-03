// Package compat holds compatibility functions for interoperability between
// forks or different libraries for the same purpose.
package compat

import (
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	gokrb5ForkConfig "github.com/oiweiwei/gokrb5.fork/v9/config"
	gokrb5ForkCredentials "github.com/oiweiwei/gokrb5.fork/v9/credentials"
	gokrb5ForkKeytab "github.com/oiweiwei/gokrb5.fork/v9/keytab"
	gokrb5ForkTypes "github.com/oiweiwei/gokrb5.fork/v9/types"

	"github.com/jcmturner/gokrb5/v8/types"
)

func Gokrb5ForkV9KerberosConfig(cfg *config.Config) *gokrb5ForkConfig.Config {
	realms := make([]gokrb5ForkConfig.Realm, 0, len(cfg.Realms))

	for _, realm := range cfg.Realms {
		realms = append(realms, gokrb5ForkConfig.Realm(realm))
	}

	return &gokrb5ForkConfig.Config{
		LibDefaults: gokrb5ForkConfig.LibDefaults(cfg.LibDefaults),
		Realms:      realms,
		DomainRealm: gokrb5ForkConfig.DomainRealm(cfg.DomainRealm),
	}
}

func Gokrb5ForkV9CCache(ccache *credentials.CCache) *gokrb5ForkCredentials.CCache {
	creds := make([]*gokrb5ForkCredentials.Credential, 0, len(ccache.Credentials))

	for _, cred := range ccache.Credentials {
		addrs := make([]gokrb5ForkTypes.HostAddress, 0, len(cred.Addresses))

		for _, addr := range cred.Addresses {
			addrs = append(addrs, gokrb5ForkTypes.HostAddress(addr))
		}

		adEntries := make([]gokrb5ForkTypes.AuthorizationDataEntry, 0, len(cred.AuthData))

		for _, adEntry := range cred.AuthData {
			adEntries = append(adEntries, gokrb5ForkTypes.AuthorizationDataEntry(adEntry))
		}

		creds = append(creds, &gokrb5ForkCredentials.Credential{
			Client:       Gokrb5ForkV9Principal(cred.Client.Realm, cred.Client.PrincipalName),
			Server:       Gokrb5ForkV9Principal(cred.Server.Realm, cred.Server.PrincipalName),
			Key:          gokrb5ForkTypes.EncryptionKey(cred.Key),
			AuthTime:     cred.AuthTime,
			StartTime:    cred.StartTime,
			EndTime:      cred.EndTime,
			RenewTill:    cred.RenewTill,
			IsSKey:       cred.IsSKey,
			TicketFlags:  cred.TicketFlags,
			Addresses:    addrs,
			AuthData:     adEntries,
			Ticket:       cred.Ticket,
			SecondTicket: cred.SecondTicket,
		})
	}

	return &gokrb5ForkCredentials.CCache{
		Version:          ccache.Version,
		DefaultPrincipal: Gokrb5ForkV9Principal(ccache.DefaultPrincipal.Realm, ccache.DefaultPrincipal.PrincipalName),
		Credentials:      creds,
		Path:             ccache.Path,
	}
}

func Gokrb5ForkV9Principal(realm string, principalName types.PrincipalName) gokrb5ForkCredentials.Principal {
	return gokrb5ForkCredentials.Principal{
		Realm:         realm,
		PrincipalName: gokrb5ForkTypes.PrincipalName(principalName),
	}
}

func Gokrb5ForkV9Keytab(keytab *keytab.Keytab) *gokrb5ForkKeytab.Keytab {
	entries := make([]gokrb5ForkKeytab.Entry, 0, len(keytab.Entries))

	for _, entry := range keytab.Entries {
		entries = append(entries, gokrb5ForkKeytab.Entry{
			Principal: gokrb5ForkKeytab.Principal{
				NumComponents: entry.Principal.NumComponents,
				Realm:         entry.Principal.Realm,
				Components:    entry.Principal.Components,
				NameType:      entry.Principal.NameType,
			},
			Timestamp: entry.Timestamp,
			KVNO8:     entry.KVNO8,
			Key:       gokrb5ForkTypes.EncryptionKey(entry.Key),
			KVNO:      entry.KVNO,
		})
	}

	return &gokrb5ForkKeytab.Keytab{
		Version: 2,
		Entries: entries,
	}
}
