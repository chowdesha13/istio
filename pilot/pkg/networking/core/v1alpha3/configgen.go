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

package v1alpha3

import (
	"github.com/golang/protobuf/ptypes/any"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/plugin"
	"istio.io/istio/pilot/pkg/networking/util"
)

// To avoid a recoursive depenency to v2.
const (
	typePrefix = "type.googleapis.com/envoy.api.v2."

	// Constants used for XDS

	// ClusterType is used for cluster discovery. Typically first request received
	ClusterType = typePrefix + "Cluster"
	// ListenerType is sent after clusters and endpoints.
	ListenerType = typePrefix + "Listener"
	// RouteType is sent after listeners.
	RouteType = typePrefix + "RouteConfiguration"
	// RouteType is sent after listeners.
	EndpointType = typePrefix + "ClusterLoadAssignment"
)

type ConfigGeneratorImpl struct {
	// List of plugins that modify code generated by this config generator
	Plugins []plugin.Plugin
}

func NewConfigGenerator(plugins []plugin.Plugin) *ConfigGeneratorImpl {
	return &ConfigGeneratorImpl{
		Plugins: plugins,
	}
}

// Called when mesh config is changed.
func (configgen *ConfigGeneratorImpl) MeshConfigChanged(mesh *meshconfig.MeshConfig) {
	resetCachedListenerConfig(mesh)
}

func (configgen *ConfigGeneratorImpl) Generate(node *model.Proxy, push *model.PushContext, w *model.WatchedResource) []*any.Any {
	resp := []*any.Any{}
	switch w.TypeUrl {
	case ListenerType:
		ll := configgen.BuildListeners(node, push)
		for _, l := range ll {
			resp = append(resp, util.MessageToAny(l))
		}
	case ClusterType:
		cl := configgen.BuildClusters(node, push)
		for _, l := range cl {
			resp = append(resp, util.MessageToAny(l))
		}
	case RouteType:
		rl := configgen.BuildHTTPRoutes(node, push, w.ResourceNames)
		for _, l := range rl {
			resp = append(resp, util.MessageToAny(l))
		}
	}

	return resp
}
