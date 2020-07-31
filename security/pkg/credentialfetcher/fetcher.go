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

// credentailfetcher fetches workload credentials through platform plugins.
package credentialfetcher

import (
	"fmt"

	"istio.io/istio/security/pkg/credentialfetcher/plugin"
	"istio.io/pkg/log"
	"istio.io/istio/pkg/security"
)

var (
	credentialLog = log.RegisterScope("credential", "Credential fetcher for istio agent", 0)
)

func NewCredFetcher(platform, trustdomain, jwtPath string) (security.CredFetcher, error) {
	switch platform {
	case security.K8S:
		return plugin.CreateK8SPlugin(credentialLog, jwtPath), nil
	case security.GCE:
		return plugin.CreateGCEPlugin(credentialLog, trustdomain, jwtPath), nil
	case security.Mock: // for test only
		return plugin.CreateMockPlugin(credentialLog), nil
	default:
		return nil, fmt.Errorf("invalid platform %s", platform)
	}
}
