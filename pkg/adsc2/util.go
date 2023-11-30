// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package adsc2

import (
	"crypto/tls"
	"sync"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"istio.io/istio/pilot/pkg/xds"
	"istio.io/istio/pkg/security"
)

func getClientCertFn(config *Config) func(requestInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if config.SecretManager != nil {
		return func(requestInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			key, err := config.SecretManager.GenerateSecret(security.WorkloadKeyCertResourceName)
			if err != nil {
				return nil, err
			}
			clientCert, err := tls.X509KeyPair(key.CertificateChain, key.PrivateKey)
			if err != nil {
				return nil, err
			}
			return &clientCert, nil
		}
	}
	if config.CertDir != "" {
		return func(requestInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			certName := config.CertDir + "/cert-chain.pem"
			clientCert, err := tls.LoadX509KeyPair(certName, config.CertDir+"/key.pem")
			if err != nil {
				return nil, err
			}
			return &clientCert, nil
		}
	}

	return nil
}

func isDebugType(typeURL string) bool {
	return typeURL == xds.TypeDebugSyncronization || typeURL == xds.TypeDebugConfigDump || typeURL == xds.TypeURLConnect
}

type cache struct {
	mu        sync.RWMutex
	resources map[resourceKey]*discovery.Resource
}

func newResourceCache() *cache {
	return &cache{
		resources: make(map[resourceKey]*discovery.Resource),
	}
}

func (c *cache) put(key resourceKey, resource *discovery.Resource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resources[key] = resource
}

func (c *cache) get(key resourceKey) *discovery.Resource {
	c.mu.RLock()
	defer c.mu.RUnlock()
	res := c.resources[key]
	return res
}

func (c *cache) delete(key resourceKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.resources, key)
}
