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

package platform

import (
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

// Environment provides information for the platform on which the bootstrapping
// is taking place.
type Environment interface {
	// Metadata returns a collection of environmental metadata, structured
	// as a map for metadata names to values. An example for GCP would be a
	// mapping from "gcp_project" to "2344534543". Keys should be prefixed
	// by the short name for the platform (example: "gcp_").
	Metadata() map[string]string

	// Locality returns the run location for the bootstrap transformed from the
	// platform-specific representation into the Envoy Locality schema.
	Locality() *corev3.Locality
}

// Unknown provides a default platform environment for cases in which the platform
// on which the bootstrapping is taking place cannot be determined.
type Unknown struct{}

// Metadata returns an empty map.
func (*Unknown) Metadata() map[string]string {
	return map[string]string{}
}

// Locality returns an empty core.Locality struct.
func (*Unknown) Locality() *corev3.Locality {
	return &corev3.Locality{}
}
