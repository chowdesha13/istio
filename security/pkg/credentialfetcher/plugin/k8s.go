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

// This is k8s plugin of credentialfetcher.
package plugin

import (
	"io/ioutil"

	"istio.io/pkg/log"
)

// The plugin object.
type K8SPlugin struct {
	// Log scope
	credlog *log.Scope

	jwtPath string
}

// CreateK8SPlugin creates a k8s credential fetcher plugin. Return the pointer to the created plugin.
func CreateK8SPlugin(scope *log.Scope, jwtPath string) *K8SPlugin {
	p := &K8SPlugin{
		credlog: scope,
		jwtPath: jwtPath,
	}
	return p
}

// GetPlatformCredential gets k8s jwt token from a path.
func (p *K8SPlugin) GetPlatformCredential() (string, error) {
	token, err := ioutil.ReadFile(p.jwtPath)
	if err != nil {
		p.credlog.Errorf("Failed to get k8s jwt token from %s: %v", p.jwtPath, err)
		return "", err
	}
	return string(token), nil
}
