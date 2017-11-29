// Copyright 2017 Istio Authors
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

package proxy

import (
	"fmt"
	"time"

	"istio.io/istio/tests/integration/component"
	"istio.io/istio/tests/util"
)

// LocalComponent is a component of local proxy binary in process
type LocalComponent struct {
	component.CommonProcesssComp
}

// NewLocalComponent create a LocalComponent with name and log dir
func NewLocalComponent(n, binaryPath, logDir string) *LocalComponent {
	logFile := fmt.Sprintf("%s/%s.log", logDir, n)

	return &LocalComponent{
		CommonProcesssComp: component.CommonProcesssComp{
			CommonComp: component.CommonComp{
				Name:    n,
				LogFile: logFile,
			},
			BinaryPath: binaryPath,
		},
	}
}

// Start brings up a local envoy using start_envory script from istio/proxy
func (proxyComp *LocalComponent) Start() (err error) {
	proxyComp.Process, err = util.RunBackground(fmt.Sprintf("%s > %s 2>&1",
		"/Users/yutongz/go/src/istio.io/istio/integration_tmp/usr/local/bin/envoy", proxyComp.LogFile))

	// TODO: Find more reliable way to tell if local components are ready to serve
	time.Sleep(3 * time.Second)
	return
}

// IsAlive check the process of local server is running
// TODO: Process running doesn't guarantee server is ready
// TODO: Need a better way to check if component is alive/running
func (proxyComp *LocalComponent) IsAlive() (bool, error) {
	return util.IsProcessRunning(proxyComp.Process)
}

// Cleanup clean up tmp files and other resource created by LocalComponent
func (proxyComp *LocalComponent) Cleanup() error {
	return nil
}
