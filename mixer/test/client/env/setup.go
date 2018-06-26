// Copyright 2017 Istio Authors. All Rights Reserved.
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

package env

import (
	"encoding/json"
	"fmt"
	"log"
	"testing"
	"time"

	rpc "github.com/gogo/googleapis/google/rpc"

	mixerpb "istio.io/api/mixer/v1"
	"istio.io/istio/pkg/test"
)

// TestSetup store data for a test.
type TestSetup struct {
	t      *testing.T
	epoch  int
	mfConf *MixerFilterConf
	ports  *Ports

	envoy              *Envoy
	mixer              *MixerServer
	backend            *HTTPServer
	testName           uint16
	stress             bool
	filtersBeforeMixer string
	noMixer            bool
	noProxy            bool
	noBackend          bool
	disableHotRestart  bool

	// EnvoyTemplate is the bootstrap config used by envoy.
	EnvoyTemplate string

	// EnvoyParams contain extra envoy parameters to pass in the CLI (cluster, node)
	EnvoyParams []string

	// EnvoyConfigOpt allows passing additional parameters to the EnvoyTemplate
	EnvoyConfigOpt map[string]interface{}

	// IstioSrc is the base directory of istio sources. May be set for finding testdata or
	// other files in the source tree
	IstioSrc string

	// IstioOut is the base output directory.
	IstioOut string

	// AccessLogPath is the access log path for Envoy
	AccessLogPath string
}

// NewTestSetup creates a new test setup
// "name" has to be defined in ports.go
func NewTestSetup(name uint16, t *testing.T) *TestSetup {
	return &TestSetup{
		t:             t,
		mfConf:        GetDefaultMixerFilterConf(),
		ports:         NewPorts(name),
		testName:      name,
		AccessLogPath: "/tmp/envoy-access.log",
	}
}

// MfConfig get Mixer filter config
func (s *TestSetup) MfConfig() *MixerFilterConf {
	return s.mfConf
}

// Ports get ports object
func (s *TestSetup) Ports() *Ports {
	return s.ports
}

// SetMixerCheckReferenced set Referenced in mocked Check response
func (s *TestSetup) SetMixerCheckReferenced(ref *mixerpb.ReferencedAttributes) {
	s.mixer.checkReferenced = ref
}

// SetMixerQuotaReferenced set Referenced in mocked Quota response
func (s *TestSetup) SetMixerQuotaReferenced(ref *mixerpb.ReferencedAttributes) {
	s.mixer.quotaReferenced = ref
}

// SetMixerCheckStatus set Status in mocked Check response
func (s *TestSetup) SetMixerCheckStatus(status rpc.Status) {
	s.mixer.check.rStatus = status
}

// SetMixerQuotaStatus set Status in mocked Quota response
func (s *TestSetup) SetMixerQuotaStatus(status rpc.Status) {
	s.mixer.quota.rStatus = status
}

// SetMixerQuotaLimit set mock quota limit
func (s *TestSetup) SetMixerQuotaLimit(limit int64) {
	s.mixer.quotaLimit = limit
}

// GetMixerQuotaCount get the number of Quota calls.
func (s *TestSetup) GetMixerQuotaCount() int {
	return s.mixer.quota.Count()
}

// GetMixerCheckCount get the number of Check calls.
func (s *TestSetup) GetMixerCheckCount() int {
	return s.mixer.check.Count()
}

// GetMixerReportCount get the number of Report calls.
func (s *TestSetup) GetMixerReportCount() int {
	return s.mixer.report.Count()
}

// SetStress set the stress flag
func (s *TestSetup) SetStress(stress bool) {
	s.stress = stress
}

// SetNoMixer set NoMixer flag
func (s *TestSetup) SetNoMixer(no bool) {
	s.noMixer = no
}

// SetFiltersBeforeMixer sets the configurations of the filters before the Mixer filter
func (s *TestSetup) SetFiltersBeforeMixer(filters string) {
	s.filtersBeforeMixer = filters
}

// SetDisableHotRestart sets whether disable the HotRestart feature of Envoy
func (s *TestSetup) SetDisableHotRestart(disable bool) {
	s.disableHotRestart = disable
}

// SetNoProxy set NoProxy flag
func (s *TestSetup) SetNoProxy(no bool) {
	s.noProxy = no
}

// SetNoBackend set NoMixer flag
func (s *TestSetup) SetNoBackend(no bool) {
	s.noBackend = no
}

// SetUp setups Envoy, Mixer, and Backend server for test.
func (s *TestSetup) SetUp() error {
	var err error
	s.envoy, err = s.NewEnvoy(s.stress, s.filtersBeforeMixer, s.mfConf, s.ports, s.epoch, s.disableHotRestart)
	if err != nil {
		log.Printf("unable to create Envoy %v", err)
		return err
	}

	err = s.envoy.Start()
	if err != nil {
		return err
	}

	if !s.noProxy {
		WaitForPort(s.ports.ClientProxyPort)
		WaitForPort(s.ports.ServerProxyPort)
	}

	if !s.noMixer {
		s.mixer, err = NewMixerServer(s.ports.MixerPort, s.stress)
		if err != nil {
			log.Printf("unable to create mixer server %v", err)
		} else {
			s.mixer.Start()
		}
	}

	if !s.noBackend {
		s.backend, err = NewHTTPServer(s.ports.BackendPort)
		if err != nil {
			log.Printf("unable to create HTTP server %v", err)
		} else {
			s.backend.Start()
		}
	}

	return nil
}

// TearDown shutdown the servers.
func (s *TestSetup) TearDown() {
	if err := s.envoy.Stop(); err != nil {
		s.t.Errorf("error quitting envoy: %v", err)
	}
	if s.mixer != nil {
		s.mixer.Stop()
	}

	if s.backend != nil {
		s.backend.Stop()
	}
}

// ReStartEnvoy restarts Envoy
func (s *TestSetup) ReStartEnvoy() {
	_ = s.envoy.Stop()
	s.ports = NewEnvoyPorts(s.ports, s.testName)
	log.Printf("new allocated ports are %v:", s.ports)
	var err error
	s.epoch++
	s.envoy, err = s.NewEnvoy(s.stress, s.filtersBeforeMixer, s.mfConf, s.ports, s.epoch, s.disableHotRestart)
	if err != nil {
		s.t.Errorf("unable to re-start Envoy %v", err)
	} else {
		_ = s.envoy.Start()

		if !s.noProxy {
			WaitForPort(s.ports.ClientProxyPort)
			WaitForPort(s.ports.ServerProxyPort)
		}
	}
}

// VerifyCheckCount verifies the number of Check calls.
func (s *TestSetup) VerifyCheckCount(tag string, expected int) {
	s.t.Helper()
	test.Eventually(s.t, "VerifyCheckCount", func() bool {
		return s.mixer.check.Count() == expected
	})
}

// VerifyReportCount verifies the number of Report calls.
func (s *TestSetup) VerifyReportCount(tag string, expected int) {
	s.t.Helper()
	test.Eventually(s.t, "VerifyReportCount", func() bool {
		return s.mixer.report.Count() == expected
	})
}

// VerifyCheck verifies Check request data.
func (s *TestSetup) VerifyCheck(tag string, result string) {
	s.t.Helper()
	bag := <-s.mixer.check.ch
	if err := Verify(bag, result); err != nil {
		s.t.Fatalf("Failed to verify %s check: %v\n, Attributes: %+v",
			tag, err, bag)
	}
}

// VerifyReport verifies Report request data.
func (s *TestSetup) VerifyReport(tag string, result string) {
	s.t.Helper()
	bag := <-s.mixer.report.ch
	if err := Verify(bag, result); err != nil {
		s.t.Fatalf("Failed to verify %s report: %v\n, Attributes: %+v",
			tag, err, bag)
	}
}

// VerifyQuota verified Quota request data.
func (s *TestSetup) VerifyQuota(tag string, name string, amount int64) {
	s.t.Helper()
	<-s.mixer.quota.ch
	if s.mixer.qma.Quota != name {
		s.t.Fatalf("Failed to verify %s quota name: %v, expected: %v\n",
			tag, s.mixer.qma.Quota, name)
	}
	if s.mixer.qma.Amount != amount {
		s.t.Fatalf("Failed to verify %s quota amount: %v, expected: %v\n",
			tag, s.mixer.qma.Amount, amount)
	}
}

// WaitForStatsUpdateAndGetStats waits for waitDuration seconds to let Envoy update stats, and sends
// request to Envoy for stats. Returns stats response.
func (s *TestSetup) WaitForStatsUpdateAndGetStats(waitDuration int) (string, error) {
	time.Sleep(time.Duration(waitDuration) * time.Second)
	statsURL := fmt.Sprintf("http://localhost:%d/stats?format=json&usedonly", s.Ports().AdminPort)
	code, respBody, err := HTTPGet(statsURL)
	if err != nil {
		return "", fmt.Errorf("sending stats request returns an error: %v", err)
	}
	if code != 200 {
		return "", fmt.Errorf("sending stats request returns unexpected status code: %d", code)
	}
	return respBody, nil
}

type statEntry struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

type stats struct {
	StatList []statEntry `json:"stats"`
}

// UnmarshalStats Unmarshals Envoy stats from JSON format into a map, where stats name is
// key, and stats value is value.
func (s *TestSetup) unmarshalStats(statsJSON string) map[string]int {
	statsMap := make(map[string]int)

	var statsArray stats
	if err := json.Unmarshal([]byte(statsJSON), &statsArray); err != nil {
		s.t.Fatalf("unable to unmarshal stats from json")
	}

	for _, v := range statsArray.StatList {
		statsMap[v.Name] = v.Value
	}
	return statsMap
}

// VerifyStats verifies Envoy stats.
func (s *TestSetup) VerifyStats(expectedStats map[string]int) {
	s.t.Helper()

	check := func(actualStatsMap map[string]int) error {
		for eStatsName, eStatsValue := range expectedStats {
			aStatsValue, ok := actualStatsMap[eStatsName]
			if !ok && eStatsValue != 0 {
				return fmt.Errorf("failed to find expected stat %s", eStatsName)
			}
			if aStatsValue != eStatsValue {
				return fmt.Errorf("stats %s does not match. expected vs actual: %d vs %d",
					eStatsName, eStatsValue, aStatsValue)
			}

			log.Printf("stat %s is matched. value is %d", eStatsName, eStatsValue)
		}
		return nil
	}

	delay := 200 * time.Millisecond
	total := 3 * time.Second

	var err error
	for attempt := 0; attempt < int(total/delay); attempt++ {
		statsURL := fmt.Sprintf("http://localhost:%d/stats?format=json&usedonly", s.Ports().AdminPort)
		code, respBody, errGet := HTTPGet(statsURL)
		if errGet != nil {
			log.Printf("sending stats request returns an error: %v", errGet)
		} else if code != 200 {
			log.Printf("sending stats request returns unexpected status code: %d", code)
		} else {
			actualStatsMap := s.unmarshalStats(respBody)
			if err = check(actualStatsMap); err == nil {
				return
			}
			log.Printf("failed to verify stats: %v", err)
		}
		time.Sleep(delay)
	}
	s.t.Errorf("failed to find expected stats: %v", err)
}

// VerifyStatsLT verifies that Envoy stats contains stat expectedStat, whose value is less than
// expectedStatVal.
func (s *TestSetup) VerifyStatsLT(actualStats string, expectedStat string, expectedStatVal int) {
	s.t.Helper()
	actualStatsMap := s.unmarshalStats(actualStats)

	aStatsValue, ok := actualStatsMap[expectedStat]
	if !ok {
		s.t.Fatalf("Failed to find expected Stat %s\n", expectedStat)
	} else if aStatsValue >= expectedStatVal {
		s.t.Fatalf("Stat %s does not match. Expected value < %d, actual stat value is %d",
			expectedStat, expectedStatVal, aStatsValue)
	} else {
		log.Printf("stat %s is matched. %d < %d", expectedStat, aStatsValue, expectedStatVal)
	}
}

// DrainMixerAllChannels drain all channels
func (s *TestSetup) DrainMixerAllChannels() {
	go func() {
		for {
			<-s.mixer.check.ch
		}
	}()
	go func() {
		for {
			<-s.mixer.report.ch
		}
	}()
	go func() {
		for {
			<-s.mixer.quota.ch
		}
	}()
}
