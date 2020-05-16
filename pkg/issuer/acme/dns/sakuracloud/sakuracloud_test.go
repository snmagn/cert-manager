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

package sakuracloud

import (
	"os"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
)

var (
	sakuraCloudLiveTest bool
	sakuraCloudToken    string
	sakuraCloudSecret   string
	sakuraCloudDomain   string
)

func init() {
	sakuraCloudToken = os.Getenv("SAKURACLOUD_ACCESS_TOKEN")
	sakuraCloudSecret = os.Getenv("SAKURACLOUD_ACCESS_TOKEN_SECRET")
	sakuraCloudDomain = os.Getenv("SAKURACLOUD_DOMAIN")
	if len(sakuraCloudToken) > 0 && len(sakuraCloudSecret) > 0 && len(sakuraCloudDomain) > 0 {
		sakuraCloudLiveTest = true
	}
}

func restoreEnv() {
	os.Setenv("SAKURACLOUD_ACCESS_TOKEN", sakuraCloudToken)
	os.Setenv("SAKURACLOUD_ACCESS_TOKEN_SECRET", sakuraCloudSecret)
}

func TestNewDNSProviderValid(t *testing.T) {
	os.Setenv("SAKURACLOUD_ACCESS_TOKEN", "")
	os.Setenv("SAKURACLOUD_ACCESS_TOKEN_SECRET", "")
	_, err := NewDNSProviderCredentials("123", "456", util.RecursiveNameservers)
	assert.NoError(t, err)
	restoreEnv()
}

func TestNewDNSProviderValidEnv(t *testing.T) {
	os.Setenv("SAKURACLOUD_ACCESS_TOKEN", "123")
	os.Setenv("SAKURACLOUD_ACCESS_TOKEN_SECRET", "456")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.NoError(t, err)
	restoreEnv()
}

func TestNewDNSProviderMissingTokenErr(t *testing.T) {
	os.Setenv("SAKURACLOUD_ACCESS_TOKEN", "")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.EqualError(t, err, "SakuraCloud token missing")
	restoreEnv()
}

func TestNewDNSProviderMissingSecretErr(t *testing.T) {
	os.Setenv("SAKURACLOUD_ACCESS_TOKEN_SECRET", "")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.EqualError(t, err, "SakuraCloud secret missing")
	restoreEnv()
}

func TestSakuraCloudPresent(t *testing.T) {
	if !sakuraCloudLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(sakuraCloudToken, sakuraCloudSecret, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present(sakuraCloudDomain, "_acme-challenge."+sakuraCloudDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestSakuraCloudCleanUp(t *testing.T) {
	if !sakuraCloudLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 2)

	provider, err := NewDNSProviderCredentials(sakuraCloudToken, sakuraCloudSecret, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.CleanUp(sakuraCloudDomain, "_acme-challenge."+sakuraCloudDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestSakuraCloudSolveForProvider(t *testing.T) {

}
