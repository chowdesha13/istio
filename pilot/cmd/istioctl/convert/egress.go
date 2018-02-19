// Copyright 2017 Istio Authors.
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

package convert

import (
	"fmt"

	routing "istio.io/api/routing/v1alpha1"
	routingv2 "istio.io/api/routing/v1alpha2"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/log"
)

func convertEgressRules(configs []model.Config) []model.Config {
	egressRules := make([]*routing.EgressRule, 0)
	for _, config := range configs {
		if config.Type == model.EgressRule.Type {
			egressRules = append(egressRules, config.Spec.(*routing.EgressRule))
		}
	}

	externalServices := make([]*routingv2.ExternalService, 0)
	for _, egressRule := range egressRules {
		host := convertIstioService(egressRule.Destination)

		ports := make([]*routingv2.Port, 0)
		for _, egressPort := range egressRule.Ports {
			ports = append(ports, &routingv2.Port{
				Name:     fmt.Sprintf("%s-%d", egressPort.Protocol, egressPort.Port),
				Protocol: egressPort.Protocol,
				Number:   uint32(egressPort.Port),
			})
		}

		if egressRule.UseEgressProxy {
			log.Warnf("Use egress proxy field not supported")
		}

		externalServices = append(externalServices, &routingv2.ExternalService{
			Hosts:     []string{host},
			Ports:     ports,
			Discovery: routingv2.ExternalService_NONE,
		})
	}

	out := make([]model.Config, 0)
	for _, externalServices := range externalServices {
		out = append(out, model.Config{
			ConfigMeta: model.ConfigMeta{
				Type:            model.ExternalService.Type,
				Name:            "FIXME",
				Namespace:       "FIXME",
				Domain:          "FIXME",
				Labels:          nil,
				Annotations:     nil,
				ResourceVersion: "FIXME",
			},
			Spec: externalServices,
		})
	}

	return out
}
