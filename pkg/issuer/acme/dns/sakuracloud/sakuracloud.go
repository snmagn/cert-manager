/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package sakuracloud implements a DNS provider for solving the DNS-01
// challenge using sakuracloud DNS.
package sakuracloud

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/sacloud/libsacloud/v2/sacloud"
	"github.com/sacloud/libsacloud/v2/sacloud/search"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	client           sacloud.DNSAPI
}

// NewDNSProvider returns a DNSProvider instance configured for sakuracloud.
// The access token must be passed in the environment variable DIGITALOCEAN_TOKEN
func NewDNSProvider(dns01Nameservers []string) (*DNSProvider, error) {
	token := os.Getenv("SAKURACLOUD_ACCESS_TOKEN")
	secret := os.Getenv("SAKURACLOUD_ACCESS_TOKEN_SECRET")
	return NewDNSProviderCredentials(token, secret, dns01Nameservers)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for sakuracloud.
func NewDNSProviderCredentials(token, secret string, dns01Nameservers []string) (*DNSProvider, error) {
	if token == "" {
		return nil, fmt.Errorf("SakuraCloud token missing")
	}
	if secret == "" {
		return nil, fmt.Errorf("SakuraCloud secret missing")
	}

	caller := &sacloud.Client{
		AccessToken:       token,
		AccessTokenSecret: secret,
		UserAgent:         "sacloud/cert-manager",
		RetryMax:          sacloud.APIDefaultRetryMax,
		RetryWaitMin:      sacloud.APIDefaultRetryWaitMin,
		RetryWaitMax:      sacloud.APIDefaultRetryWaitMax,
	}

	return &DNSProvider{
		dns01Nameservers: dns01Nameservers,
		client:           sacloud.NewDNSOp(caller),
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(domain, fqdn, value string) error {
	// if DigitalOcean does not have this zone then we will find out later
	zoneName, err := util.FindZoneByFqdn(fqdn, c.dns01Nameservers)
	if err != nil {
		return err
	}

	// check if the record has already been created
	zone, err := c.findTargetZone(fqdn)
	if err != nil {
		return err
	}
	for _, record := range zone.Records {
		if record.Type == "TXT" && record.RData == value {
			return nil
		}

	}

	targetName := fqdn
	if strings.HasSuffix(fqdn, zoneName) {
		targetName = util.UnFqdn(fqdn[:len(fqdn)-len(zoneName)])
	}
	zone.Records = append(zone.Records, &sacloud.DNSRecord{
		Type:  "TXT",
		Name:  targetName,
		RData: value,
		TTL:   60,
	})

	zone, err = c.client.UpdateSettings(context.Background(), zone.ID, &sacloud.DNSUpdateSettingsRequest{
		Records: zone.Records,
	})
	if err != nil {
		return err
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, fqdn, value string) error {
	// check if the record has already been created
	zone, err := c.findTargetZone(fqdn)
	if err != nil {
		return err
	}
	var records []*sacloud.DNSRecord
	for _, record := range zone.Records {
		if record.Type != "TXT" || record.RData != value {
			records = append(records, record)
		}

	}

	zone, err = c.client.UpdateSettings(context.Background(), zone.ID, &sacloud.DNSUpdateSettingsRequest{
		Records: records,
	})
	if err != nil {
		return err
	}

	return nil
}

func (c *DNSProvider) findTargetZone(fqdn string) (*sacloud.DNS, error) {
	zoneName, err := util.FindZoneByFqdn(fqdn, c.dns01Nameservers)
	if err != nil {
		return nil, err
	}

	searched, err := c.client.Find(
		context.Background(),
		&sacloud.FindCondition{
			Filter: search.Filter{
				search.Key("Name"): util.UnFqdn(zoneName),
			},
		},
	)
	if err != nil {
		return nil, err
	}
	if searched.Count != 1 {
		return nil, fmt.Errorf("DNS Zone found more than 1: zoneName: %s", util.UnFqdn(zoneName))
	}

	return searched.DNS[0], err
}
