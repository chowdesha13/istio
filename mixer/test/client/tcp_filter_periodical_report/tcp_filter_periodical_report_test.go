// Copyright 2018 Istio Authors. All Rights Reserved.
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

package tcpFilterPeriodicalReport

import (
	"fmt"
	"testing"

	"istio.io/istio/mixer/test/client/env"
)

// Report attributes from a good POST request
const deltaReportAttributesOkPost = `
{
  "context.protocol": "tcp",
  "context.time": "*",
  "mesh1.ip": "[1 1 1 1]",
  "source.ip": "[127 0 0 1]",
  "source.port": "*",
  "target.uid": "POD222",
  "target.namespace": "XYZ222",
  "destination.ip": "[127 0 0 1]",
  "destination.port": "*",
  "connection.mtls": false,
  "connection.received.bytes": 191,
  "connection.received.bytes_total": 191,
  "connection.sent.bytes": 0,
  "connection.sent.bytes_total": 0
}
`
const finalReportAttributesOkPost = `
{
  "context.protocol": "tcp",
  "context.time": "*",
  "mesh1.ip": "[1 1 1 1]",
  "source.ip": "[127 0 0 1]",
  "source.port": "*",
  "target.uid": "POD222",
  "target.namespace": "XYZ222",
  "destination.ip": "[127 0 0 1]",
  "destination.port": "*",
  "connection.mtls": false,
  "connection.received.bytes": 0,
  "connection.received.bytes_total": 191,
  "connection.sent.bytes": 138,
  "connection.sent.bytes_total": 138,
  "connection.duration": "*"
}
`

func TestTCPMixerFilterPeriodicalReport(t *testing.T) {
	s := env.NewTestSetup(env.TCPMixerFilterPeriodicalReportTest, t)
	env.SetTCPReportInterval(s.V2().TCPServerConf, 2)
	if err := s.SetUp(); err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}
	defer s.TearDown()

	// Sends a request to /slowresponse, so that client receives response after 3 seconds.
	// Mixerclient sends a delta report after 2 seconds, and sends a final report after another 1
	// second.
	url := fmt.Sprintf("http://localhost:%d/echo?delay=3", s.Ports().TCPProxyPort)

	tag := "OKPost"
	if _, _, err := env.ShortLiveHTTPPost(url, "text/plain", "Get Slow Response"); err != nil {
		t.Errorf("Failed in request %s: %v", tag, err)
	}

	s.VerifyReport("deltaReport", deltaReportAttributesOkPost)
	s.VerifyReport("finalReport", finalReportAttributesOkPost)
}
