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

package model

import (
	"github.com/gogo/protobuf/proto"

	"istio.io/api/annotation"
	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/api/networking/v1beta1"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/istio/pkg/util/gogoprotomarshal"
	istiolog "istio.io/pkg/log"
)

var pclog = istiolog.RegisterScope("proxyconfig", "Istio ProxyConfig", 0)

// ProxyConfigs organizes ProxyConfig configuration by namespace.
type ProxyConfigs struct {
	// namespaceToProxyConfigs
	namespaceToProxyConfigs map[string][]*v1beta1.ProxyConfig

	// root namespace
	rootNamespace string
}

// EffectiveProxyConfig generates the correct merged ProxyConfig for a given ProxyConfigTarget.
func (p *ProxyConfigs) EffectiveProxyConfig(node *Proxy, mc *meshconfig.MeshConfig) *meshconfig.ProxyConfig {
	if p == nil || node == nil {
		return nil
	}

	defaultConfig := mesh.DefaultProxyConfig()
	effectiveProxyConfig := &defaultConfig

	// Merge the proxy config from default config.
	effectiveProxyConfig = mergeWithPrecedence(mc.GetDefaultConfig(), effectiveProxyConfig)
	if p.rootNamespace != "" {
		effectiveProxyConfig = mergeWithPrecedence(p.mergedGlobalConfig(), effectiveProxyConfig)
	}

	if node.Metadata.Namespace != p.rootNamespace {
		namespacedConfig := p.mergedNamespaceConfig(node.Metadata.Namespace)
		effectiveProxyConfig = mergeWithPrecedence(namespacedConfig, effectiveProxyConfig)
	}

	workloadConfig := p.mergedWorkloadConfig(node.Metadata.Namespace, node.Metadata.Labels)

	// Check for proxy.istio.io/config annotation and merge it with lower priority than the
	// workload-matching ProxyConfig CRs.
	if v, ok := node.Metadata.Annotations[annotation.ProxyConfig.Name]; ok {
		pca, err := proxyConfigFromAnnotation(v)
		if err == nil {
			workloadConfig = mergeWithPrecedence(workloadConfig, pca)
		}
	}
	effectiveProxyConfig = mergeWithPrecedence(workloadConfig, effectiveProxyConfig)

	return effectiveProxyConfig
}

func GetProxyConfigs(env *Environment) (*ProxyConfigs, error) {
	proxyconfigs := &ProxyConfigs{
		namespaceToProxyConfigs: map[string][]*v1beta1.ProxyConfig{},
		rootNamespace:           env.Mesh().GetRootNamespace(),
	}
	resources, err := env.List(collections.IstioNetworkingV1Beta1Proxyconfigs.Resource().GroupVersionKind(), NamespaceAll)
	if err != nil {
		return nil, err
	}
	for _, resource := range resources {
		proxyconfigs.namespaceToProxyConfigs[resource.Namespace] =
			append(proxyconfigs.namespaceToProxyConfigs[resource.Namespace], resource.Spec.(*v1beta1.ProxyConfig))
	}
	return proxyconfigs, nil
}

func (p *ProxyConfigs) mergedGlobalConfig() *meshconfig.ProxyConfig {
	return p.mergedNamespaceConfig(p.rootNamespace)
}

// mergedWorkloadConfig merges ProxyConfig resources matching the given namespace.
func (p *ProxyConfigs) mergedNamespaceConfig(namespace string) *meshconfig.ProxyConfig {
	var namespaceScopedProxyConfigs []*v1beta1.ProxyConfig
	for _, pc := range p.namespaceToProxyConfigs[namespace] {
		if pc.GetSelector() == nil {
			namespaceScopedProxyConfigs = append(namespaceScopedProxyConfigs, pc)
		}
	}
	return mergeWithPrecedence(
		toMeshConfigProxyConfigList(namespaceScopedProxyConfigs)...)
}

// mergedWorkloadConfig merges ProxyConfig resources matching the given namespace and labels.
func (p *ProxyConfigs) mergedWorkloadConfig(namespace string, l map[string]string) *meshconfig.ProxyConfig {
	var workloadScopedConfigs []*v1beta1.ProxyConfig
	for _, pc := range p.namespaceToProxyConfigs[namespace] {
		if len(pc.GetSelector().GetMatchLabels()) == 0 {
			continue
		}
		match := labels.Collection{l}
		selector := labels.Instance(pc.GetSelector().GetMatchLabels())
		if match.IsSupersetOf(selector) {
			workloadScopedConfigs = append(workloadScopedConfigs, pc)
		}
	}
	return mergeWithPrecedence(
		toMeshConfigProxyConfigList(workloadScopedConfigs)...)
}

// mergeWithPrecedence merges the ProxyConfigs together with earlier items having
// the highest priority.
func mergeWithPrecedence(pcs ...*meshconfig.ProxyConfig) *meshconfig.ProxyConfig {
	merged := &meshconfig.ProxyConfig{}
	for i := len(pcs) - 1; i >= 0; i-- {
		// TODO(Monkeyanator) some fields seem not to merge when set to the type's default value
		// such as overriding with a concurrency value 0. Do we need a custom merge similar to what the
		// telemetry code does with shallowMerge?
		proto.Merge(merged, pcs[i])
		if pcs[i].GetConcurrency() != nil {
			merged.Concurrency = pcs[i].GetConcurrency()
		}
	}
	return merged
}

func toMeshConfigProxyConfigList(pcs []*v1beta1.ProxyConfig) []*meshconfig.ProxyConfig {
	pcl := make([]*meshconfig.ProxyConfig, len(pcs))
	for _, pc := range pcs {
		pcl = append(pcl, toMeshConfigProxyConfig(pc))
	}
	return pcl
}

func toMeshConfigProxyConfig(pc *v1beta1.ProxyConfig) *meshconfig.ProxyConfig {
	mcpc := &meshconfig.ProxyConfig{}
	if pc.Concurrency != nil {
		mcpc.Concurrency = pc.Concurrency
	}
	if pc.EnvironmentVariables != nil {
		mcpc.ProxyMetadata = pc.EnvironmentVariables
	}
	return mcpc
}

func proxyConfigFromAnnotation(pcAnnotation string) (*meshconfig.ProxyConfig, error) {
	pc := &meshconfig.ProxyConfig{}
	if err := gogoprotomarshal.ApplyYAML(pcAnnotation, pc); err != nil {
		return nil, err
	}
	return pc, nil
}
