// Copyright 2020 Istio Authors
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

package rotatesds

import (
	"fmt"
	"testing"
	"time"

	"istio.io/istio/mixer/test/client/env"
	sdsTest "istio.io/istio/security/pkg/nodeagent/test"
	"os/exec"
)

const (
	rotateInterval = 1 * time.Second
	proxyRunningTime = 4 * rotateInterval
	sleepTime = 100 * time.Millisecond
	httpSuccessCode = 200
	certShouldUpdateCount = 2
)

var (
	certSet = make(map[string]bool)
)

func TestCertRotation(t *testing.T) {
	sdsTest.RotateCert(rotateInterval)
	setup := sdsTest.SetupTest(t, env.SDSCertRotation)
	defer setup.TearDown()
	setup.StartProxy(t)
	start := time.Now()
	for {
		code, _, err := env.HTTPGet(fmt.Sprintf("http://localhost:%d/echo", setup.OutboundListenerPort))
		if err != nil {
			t.Errorf("Failed in request: %v", err)
		}
		if code != httpSuccessCode {
			t.Errorf("Unexpected status code: %d", code)
		}
		if time.Since(start) > proxyRunningTime {
			break
		}
		time.Sleep(sleepTime)
		cert, err := GetInboundCert(setup.InboundListenerPort)
		if err != nil {
			continue
		}
		certSet[cert] = true
	}
	numInboundCertUpdate := len(certSet) - 1
	if numInboundCertUpdate < certShouldUpdateCount {
		t.Errorf("Number of inbound Cert Update should not be less than %d, get %d", certShouldUpdateCount,numInboundCertUpdate)
	}
	/* TODO: Current the stats Map are Disabled because of performance requirement so comment out the code below
	Detailed Info:	https://github.com/istio/istio/issues/22729
	*/
	//stats, err := setup.ProxySetup.GetStatsMap()
	//if err == nil {
	//	numSSLHandshake := stats["cluster.outbound_cluster_tls.ssl.handshake"]
	//	numSSLConnError := stats[fmt.Sprintf("listener.127.0.0.1_%d.ssl.connection_error", setup.InboundListenerPort)]
	//	numSSLVerifyNoCert := stats[fmt.Sprintf("listener.127.0.0.1_%d.ssl.fail_verify_no_cert", setup.InboundListenerPort)]
	//	numSSLVerifyCAError := stats[fmt.Sprintf("listener.127.0.0.1_%d.ssl.fail_verify_error", setup.InboundListenerPort)]
	//	fmt.Printf("============4444")
	//	fmt.Printf(fmt.Sprintf("%d",setup.InboundListenerPort))
	//	numOutboundSDSUpdate := stats["cluster.outbound_cluster_tls.client_ssl_socket_factory.ssl_context_update_by_sds"]
	//	numInboundSDSUpdate := stats[fmt.Sprintf("listener.127.0.0.1_%d.server_ssl_socket_factory.ssl_context_update_by_sds", setup.InboundListenerPort)]
	//	// Cluster config max_requests_per_connection is set to 1, the number of requests should match
	//	// the number of SSL connections. This guarantees SSL connection is using the latest TLS key/cert loaded in Envoy.
	//	if numSSLHandshake != uint64(numReq) {
	//		t.Errorf("Number of successful SSL handshake does not match, expect %d but get %d", numReq, numSSLHandshake)
	//	}
	//	if numSSLConnError != 0 {
	//		t.Errorf("Number of SSL connection error: %d", numSSLConnError)
	//	}
	//	if numSSLVerifyNoCert != 0 {
	//		t.Errorf("Number of SSL handshake failures because of missing client cert: %d", numSSLVerifyNoCert)
	//	}
	//	if numSSLVerifyCAError != 0 {
	//		t.Errorf("Number of SSL handshake failures on CA verification: %d", numSSLVerifyCAError)
	//	}
	//	// Verify that there are multiple SDS updates. TLS key/cert are loaded multiple times.
	//	if numOutboundSDSUpdate <= 1 {
	//		t.Errorf("Number of SDS updates at outbound cluster should be greater than one, get %d", numOutboundSDSUpdate)
	//	}
	//	if numInboundSDSUpdate <= 1 {
	//		t.Errorf("Number of SDS updates at inbound listener should be greater than one, get %d", numInboundSDSUpdate)
	//	}
	//} else {
	//	t.Errorf("cannot get Envoy stats: %v", err)
	//}
}

// get Cert from the InboundListener
func GetInboundCert(inboundListenerPort int) (string, error) {
	return openssl("s_client", "-showcerts",
		"-connect", fmt.Sprintf("127.0.0.1:%d",inboundListenerPort),
	)
}

func openssl(args ...string) (string, error) {
	cmd := exec.Command("openssl", args...)
	out, err := cmd.Output();
	if err != nil {
		return string(out), fmt.Errorf("command %s failed: %q %v", cmd.String(), string(out), err)
	}
	return string(out), nil
}