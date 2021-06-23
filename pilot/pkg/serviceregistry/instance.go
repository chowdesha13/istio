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

package serviceregistry

import (
	"istio.io/istio/pilot/pkg/model"
)

// Instance of a service registry. A single service registry combines the capabilities of service discovery
// and the controller for managing asynchronous events.
type Instance interface {
	model.Controller
	model.ServiceDiscovery

	// Provider backing this service registry (i.e. Kubernetes etc.)
	Provider() ProviderID

	// Cluster for which the service registry applies. Only needed for multicluster systems.
	Cluster() model.ClusterID
}

var _ Instance = &Simple{}

// Simple Instance implementation, where fields are set individually.
type Simple struct {
	ProviderID ProviderID
	ClusterID  model.ClusterID

	model.Controller
	model.ServiceDiscovery
}

func (r Simple) Provider() ProviderID {
	return r.ProviderID
}

func (r Simple) Cluster() model.ClusterID {
	return r.ClusterID
}
