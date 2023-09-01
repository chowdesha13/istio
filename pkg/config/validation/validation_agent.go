//go:build agent
// +build agent

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

package validation // import "istio.io/istio/pkg/config/validation"

import (
	telemetry "istio.io/api/telemetry/v1alpha1"
)

// NOP validation that isolated `go-cel` package for istio-agent binary
func validateTelemetryFilter(filter *telemetry.AccessLogging_Filter) error {
	return nil
}
