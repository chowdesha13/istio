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
	"fmt"
	"strings"

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
	nsm := s.buildNamespaceServiceMap(ctx)
	ctx.ForEach(metadata.IstioRbacV1Alpha1Serviceroles, func(r *resource.Entry) bool {
		s.analyzeServiceRoleServices(r, ctx, nsm)
		return true
	})
}

// analyzeRoleBinding apply analysis for the service field of the given ServiceRole
func (s *ServiceRoleServicesAnalyzer) analyzeServiceRoleServices(r *resource.Entry, ctx analysis.Context, nsm map[string][]string) {
	sr := r.Item.(*v1alpha1.ServiceRole)
	ns, _ := r.Metadata.Name.InterpretAsNamespaceAndName()

	for _, rs := range sr.Rules {
		for _, svc := range rs.Services {
			// If service is * then the service role rule applies to all services on the namespace
			if svc == "*" {
				if len(nsm[ns]) < 1 {
					// Report when there are no services on the ServiceRole namespace
					ctx.Report(metadata.IstioRbacV1Alpha1Serviceroles,
						msg.NewNoResourcesNotFoundForNamespace(r, "service", ns))
				}
			} else if !s.existMatchingService(svc, nsm[ns]) {
				// Report when the specific service doesn't exist
				ctx.Report(metadata.IstioRbacV1Alpha1Serviceroles,
					msg.NewReferencedResourceNotFound(r, "service", svc))
			}
		}
	}
}

// buildNamespaceServiceMap returns a map where the index is a namespace and the boolean
func (s *ServiceRoleServicesAnalyzer) buildNamespaceServiceMap(ctx analysis.Context) map[string][]string {
	nsm := map[string][]string{}

	ctx.ForEach(metadata.K8SCoreV1Services, func(r *resource.Entry) bool {
		rns, rs := r.Metadata.Name.InterpretAsNamespaceAndName()
		nsm[rns] = append(nsm[rns], fmt.Sprintf("%s.%s.%s", rs, rns, util.DefaultKubernetesDomain))
		return true
	})

	return nsm
}

func (s *ServiceRoleServicesAnalyzer) existMatchingService(exp string, nsa []string) bool {
	m := false

	for _, svc := range nsa {
		if m = serviceMatch(exp, svc); m {
			break
		}
	}

	return m
}

func serviceMatch(expr, fqdn string) bool {
	return expr == fqdn || strings.HasPrefix(fqdn, expr) || strings.HasSuffix(fqdn, expr)
}
