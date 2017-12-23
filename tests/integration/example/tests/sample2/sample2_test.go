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

package sample2

import (
	"flag"
	"log"
	"net/http"
	"os"
	"testing"

	"istio.io/istio/tests/integration/component/mixer"
	"istio.io/istio/tests/integration/component/proxy"
	mixerEnvoyEnv "istio.io/istio/tests/integration/example/environment/mixerEnvoyEnv"
	"istio.io/istio/tests/integration/framework"
)

const (
	mixerEnvoyEnvName = "mixer_envoy_env"
	testID            = "sample2_test"
)

var (
	testEM *framework.TestEnvManager
)

func TestSample2(t *testing.T) {
	log.Printf("Running %s", testEM.TestID)

	sideCarStatus, ok := testEM.Components[1].GetStatus().(proxy.LocalCompStatus)
	if !ok {
		t.Fatalf("failed to get side car proxy status")
	}
	url := sideCarStatus.SideCarEndpoint

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("error when do request: %s", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("response code is not 200: %d", resp.StatusCode)
	}

	mixerStatus, ok := testEM.Components[2].GetStatus().(mixer.LocalCompStatus)
	if !ok {
		t.Fatalf("failed to get status of mixer component")
	}
	req, _ = http.NewRequest(http.MethodGet, mixerStatus.MetricsEndpoint, nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("error when do request: %s", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("response code is not 200: %d", resp.StatusCode)
	}

	config := testEM.Components[2].GetConfig()
	mixerConfig, ok := config.(mixer.LocalCompConfig)
	if !ok {
		t.Fatalf("failed to get config of mixer component")
	}
	log.Printf("mixer configfile Dir is: %s", mixerConfig.ConfigFileDir)

	log.Printf("%s succeeded!", testEM.TestID)
}

func TestMain(m *testing.M) {
	flag.Parse()
	testEM = framework.NewTestEnvManager(mixerEnvoyEnv.NewMixerEnvoyEnv(mixerEnvoyEnvName), testID)
	res := testEM.RunTest(m)
	log.Printf("Test result %d in env %s", res, mixerEnvoyEnvName)
	os.Exit(res)
}
