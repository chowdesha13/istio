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

package auth

import (
	"istio.io/api/rbac/v1alpha1"
	"istio.io/istio/galley/pkg/config/analysis"
	"istio.io/istio/galley/pkg/config/analysis/analyzers/util"
	"istio.io/istio/galley/pkg/config/analysis/msg"
	"istio.io/istio/galley/pkg/config/meta/metadata"
	"istio.io/istio/galley/pkg/config/meta/schema/collection"
	"istio.io/istio/galley/pkg/config/resource"
)

// ServiceRoleServicesAnalyzer checks the validity of services referred in a Service Role
type ServiceRoleServicesAnalyzer struct{}

var _ analysis.Analyzer = &ServiceRoleServicesAnalyzer{}

// Metadata implements Analyzer
func (s *ServiceRoleServicesAnalyzer) Metadata() analysis.Metadata {
	return analysis.Metadata{
		Name: "auth.ServiceRoleServicesAnalyzer",
		Inputs: collection.Names{
			metadata.IstioRbacV1Alpha1Serviceroles,
			metadata.K8SCoreV1Services,
		},
	}
}

// Analyze implements Analyzer
func (s *ServiceRoleServicesAnalyzer) Analyze(ctx analysis.Context) {
	ctx.ForEach(metadata.IstioRbacV1Alpha1Serviceroles, func(r *resource.Entry) bool {
		s.analyzeServiceRoleServices(r, ctx)
		return true
	})
}

// analyzeRoleBinding apply analysis for the service field of the given ServiceRole
func (s *ServiceRoleServicesAnalyzer) analyzeServiceRoleServices(r *resource.Entry, ctx analysis.Context) {
	sr := r.Item.(*v1alpha1.ServiceRole)
	ns, _ := r.Metadata.Name.InterpretAsNamespaceAndName()

	for _, rs := range sr.Rules {
		for _, svc := range rs.Services {
			report := false
			rn := util.GetResourceNameFromHost(ns, svc)
			_, ds := rn.InterpretAsNamespaceAndName()

			// If service is either * or *.ns.cluster
			// then the service role rule applies to all services on the namespace
			if ds == "*" {
				if !s.namespaceServicesPresent(ns, ctx) {
					// Report when there are no services on the ServiceRole namespace
					report = true
				}
			// If Service is a short name or FQDN
			// then applies to a specific service
			} else if !ctx.Exists(metadata.K8SCoreV1Services, rn) {
				// Report when the specific service doesn't exist
				report = true
			}

			if report {
				ctx.Report(metadata.IstioRbacV1Alpha1Serviceroles,
					msg.NewReferencedResourceNotFound(r, "service", svc))
			}
		}
	}
}

// namespaceServicesPresent return true when there are services for the given namespace
func (s *ServiceRoleServicesAnalyzer) namespaceServicesPresent(namespace string, ctx analysis.Context) bool {
	hs := false

	ctx.ForEach(metadata.K8SCoreV1Services, func(r *resource.Entry) bool {
		ns, _ := r.Metadata.Name.InterpretAsNamespaceAndName()
		hs = hs || ns == namespace
		return !hs
	})

	return hs
}
