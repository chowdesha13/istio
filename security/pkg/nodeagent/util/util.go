// Copyright 2019 Istio Authors
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

package util

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	pcg "github.com/prometheus/client_model/go"
)

// parseCertAndGetExpiryTimestamp parses certificate and returns cert expire time, or return error
// if fails to parse certificate.
func ParseCertAndGetExpiryTimestamp(certByte []byte) (time.Time, error) {
	block, _ := pem.Decode(certByte)
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse certificate: %v", err)
	}
	return cert.NotAfter, nil
}

// GetMetricsCounterValue returns counter value in float64
func GetMetricsCounterValue(c prometheus.Counter) (float64, error) {
	counterPb := &pcg.Metric{}
	if err := c.Write(counterPb); err != nil {
		return float64(0), err
	}
	return counterPb.GetCounter().GetValue(), nil
}
