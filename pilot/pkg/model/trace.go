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

package model

import (
	"os"
	"strconv"

	"istio.io/istio/pkg/log"
)

// Default trace sampling, if not provided in env var.
const traceSamplingDefault = 100.0

var (
	// Env var PILOT_TRACE_SAMPLING sets mesh-wide trace sampling
	// percentage, should be 0.0 - 100.0 Precision to 0.01
	traceSamplingEnv = os.Getenv("PILOT_TRACE_SAMPLING")
	traceSampling    = getTraceSampling()
)

// Return trace sampling if set correctly, or default if not.
func getTraceSampling() float64 {
	if traceSamplingEnv == "" {
		return traceSamplingDefault
	}
	f, err := strconv.ParseFloat(traceSamplingEnv, 64)
	if err != nil {
		log.Warnf("PILOT_TRACE_SAMPLING not set to a number: %v", traceSamplingEnv)
		return traceSamplingDefault
	}
	if f < 0.0 || f > 100.0 {
		log.Warnf("PILOT_TRACE_SAMPLING out of range: %v", f)
		return traceSamplingDefault
	}
	return f
}

// TraceConfig. Values are percentages 0.0 - 100.0
type TraceConfig struct {
	ClientSampling  float64
	RandomSampling  float64
	OverallSampling float64
}

// Returns configured TraceConfig
func GetTraceConfig() TraceConfig {
	return TraceConfig{
		ClientSampling:  100.0,
		RandomSampling:  traceSampling,
		OverallSampling: 100.0,
	}
}
