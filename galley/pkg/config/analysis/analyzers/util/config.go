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
	"istio.io/api/mesh/v1alpha1"
	"istio.io/istio/galley/pkg/config/analysis"
	"istio.io/istio/galley/pkg/config/meta/metadata"
	"istio.io/istio/galley/pkg/config/resource"
)

// MeshConfig returns the mesh configuration object associated with the context
// Analyzers that call this should include metadata.IstioMeshV1Alpha1MeshConfig as an input in their Metadata
func MeshConfig(ctx analysis.Context) *v1alpha1.MeshConfig {
	// Only one MeshConfig should exist in practice, but getting it this way avoids needing
	// to plumb through the name or enforce/expose a constant.
	var mc *v1alpha1.MeshConfig
	ctx.ForEach(metadata.IstioMeshV1Alpha1MeshConfig, func(r *resource.Entry) bool {
		mc = r.Item.(*v1alpha1.MeshConfig)
		return true
	})

	return mc
}

// IstioNamespace returns the Istio control plane namespace
// Analyzers that call this should include metadata.IstioMeshV1Alpha1MeshConfig as an input in their Metadata
func IstioNamespace(ctx analysis.Context) string {
	// This assumes that rootNamespace is an accurate proxy for the control plane namespace.
	// If this is ever not the case, we will need to be a bit smarter about how we get this value.
	return MeshConfig(ctx).GetRootNamespace()
}

// IsSystemNamespace returns true for namespaces that should be treated as "system" namespaces,
// and should not be analyzed using the regular rules
func IsSystemNamespace(ctx analysis.Context, ns string) bool {
	return (ns == IstioNamespace(ctx) || ns == "kube-system" || ns == "kube-public")
}
