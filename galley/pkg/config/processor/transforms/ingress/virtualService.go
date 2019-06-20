// Copyright 2019 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain ingressAdapter copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ingress

import (
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/intstr"

	"k8s.io/api/extensions/v1beta1"
	ingress "k8s.io/api/extensions/v1beta1"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/api/networking/v1alpha3"
	"istio.io/istio/galley/pkg/config/collection"
	"istio.io/istio/galley/pkg/config/event"
	"istio.io/istio/galley/pkg/config/processing"
	"istio.io/istio/galley/pkg/config/processor/metadata"
	"istio.io/istio/galley/pkg/config/resource"
	"istio.io/istio/pilot/pkg/serviceregistry/kube"
)

const (
	// IstioIngressGatewayName is the internal gateway name assigned to ingress
	IstioIngressGatewayName = "istio-autogenerated-k8s-ingress"

	// IstioIngressNamespace is the namespace where Istio ingress controller is deployed
	IstioIngressNamespace = "istio-system"
)

type virtualServiceXform struct {
	options processing.ProcessorOptions
	handler event.Handler

	ingresses map[resource.Name]*resource.Entry
	vs        map[resource.Name]*resource.Entry
}

var _ event.Transformer = &virtualServiceXform{}

// Inputs implements processing.Transformer
func (g *virtualServiceXform) Inputs() collection.Names {
	return collection.Names{metadata.K8SExtensionsV1Beta1Ingresses}
}

// Outputs implements processing.Transformer
func (g *virtualServiceXform) Outputs() collection.Names {
	return collection.Names{metadata.IstioNetworkingV1Alpha3Virtualservices}
}

// Select implements processing.Transformer
func (g *virtualServiceXform) Select(c collection.Name, h event.Handler) {
	if c == metadata.IstioNetworkingV1Alpha3Virtualservices {
		g.handler = event.CombineHandlers(g.handler, h)
	}
}

// Start implements processing.Transformer
func (g *virtualServiceXform) Start(o interface{}) {
	g.options = o.(processing.ProcessorOptions)
	g.ingresses = make(map[resource.Name]*resource.Entry)
	g.vs = make(map[resource.Name]*resource.Entry)
}

// Stop implements processing.Transformer
func (g *virtualServiceXform) Stop() {
	g.ingresses = nil
	g.vs = nil
}

// Handle implements event.Handler
func (g *virtualServiceXform) Handle(e event.Event) {
	if g.handler == nil {
		return
	}
	scope.Debugf("virtualServiceXform: Processing ingress event: %v", e)

	switch e.Kind {
	case event.Added, event.Updated:
		if g.options.MeshConfig.IngressControllerMode == meshconfig.MeshConfig_OFF {
			// short circuit and return
			return
		}
		if !shouldProcessIngress(g.options.MeshConfig, e.Entry) {
			scope.Debugf("virtualServiceXform: Skipping ingress event: %v", e)
			return
		}
		g.ingresses[e.Entry.Metadata.Name] = e.Entry

	case event.Deleted:
		if g.options.MeshConfig.IngressControllerMode == meshconfig.MeshConfig_OFF {
			// short circuit and return
			return
		}

		_, exists := g.ingresses[e.Entry.Metadata.Name]
		if !exists {
			return
		}
		delete(g.ingresses, e.Entry.Metadata.Name)

	case event.FullSync, event.Reset:
		e.Source = g.Outputs()[0]
		g.handler.Handle(e)

	default:
		scope.Errorf("virtualServiceXForm.handle: unknown event: %v", e)
	}

	g.recalculate()
}

func (g *virtualServiceXform) recalculate() {
	scope.Debug("virtualServiceXform: recalculating...")

	// TODO: this is ingressAdapter horribly inefficient way to implement this algorithm, but it is the cheapest for the time being.

	vs := make(map[resource.Name]*resource.Entry)

	ingressByHost := make(map[string]*resource.Entry)

	// Order names for stable generation.
	var orderedNames []resource.Name
	for name := range g.ingresses {
		orderedNames = append(orderedNames, name)
	}
	sort.Slice(orderedNames, func(i, j int) bool {
		return strings.Compare(orderedNames[i].String(), orderedNames[j].String()) < 0
	})

	for _, name := range orderedNames {
		entry := g.ingresses[name]

		ingress := entry.Item.(*v1beta1.IngressSpec)

		ingressToVirtualService(entry.Metadata, ingress, g.options.DomainSuffix, ingressByHost)
	}

	for _, e := range ingressByHost {
		vs[e.Metadata.Name] = e
	}

	g.generateEvents(vs)
}

func (g *virtualServiceXform) generateEvents(vs map[resource.Name]*resource.Entry) {
	scope.Debug("virtualServiceXform: generating events...")

	// generate deletes
	for k := range g.vs {
		if _, found := vs[k]; !found {
			e := event.Event{
				Kind:   event.Deleted,
				Source: g.Outputs()[0],
				Entry: &resource.Entry{
					Metadata: resource.Metadata{
						Name: k,
					},
				},
			}
			scope.Debugf("virtualServiceXform: event ==> %v", e)
			g.handler.Handle(e)
		}
	}

	// generate add
	for k, v := range vs {
		if _, found := g.vs[k]; !found {
			e := event.Event{
				Kind:   event.Added,
				Source: g.Outputs()[0],
				Entry:  v,
			}
			scope.Debugf("virtualServiceXform: event ==> %v", e)
			g.handler.Handle(e)
		}
	}

	// generate update
	for k, n := range vs {
		old, found := g.vs[k]
		if !found {
			continue
		}

		if old != n {
			e := event.Event{
				Kind:   event.Updated,
				Source: g.Outputs()[0],
				Entry:  n,
			}
			scope.Debugf("virtualServiceXform: event ==> %v", e)
			g.handler.Handle(e)
		}
	}

	g.vs = vs
}

// IngressToVirtualService converts from ingress spec to Istio VirtualServices
func ingressToVirtualService(meta resource.Metadata, i *ingress.IngressSpec,
	domainSuffix string, ingressByHost map[string]*resource.Entry) {
	// Ingress allows ingressAdapter single host - if missing '*' is assumed
	// We need to merge all rules with ingressAdapter particular host across
	// all ingresses, and return ingressAdapter separate VirtualService for each
	// host.

	namespace, name := meta.Name.InterpretAsNamespaceAndName()
	for _, rule := range i.Rules {
		if rule.HTTP == nil {
			scope.Infof("invalid ingress rule %s:%s for host %q, no paths defined", namespace, name, rule.Host)
			continue
		}

		host := rule.Host
		namePrefix := strings.Replace(host, ".", "-", -1)
		if host == "" {
			host = "*"
		}
		virtualService := &v1alpha3.VirtualService{
			Hosts:    []string{host},
			Gateways: []string{IstioIngressGatewayName},
		}

		var httpRoutes []*v1alpha3.HTTPRoute
		for _, path := range rule.HTTP.Paths {
			httpMatch := &v1alpha3.HTTPMatchRequest{
				Uri: createStringMatch(path.Path),
			}

			httpRoute := ingressBackendToHTTPRoute(&path.Backend, namespace, domainSuffix)
			if httpRoute == nil {
				scope.Infof("invalid ingress rule %s:%s for host %q, no backend defined for path", namespace, name, rule.Host)
				continue
			}
			httpRoute.Match = []*v1alpha3.HTTPMatchRequest{httpMatch}
			httpRoutes = append(httpRoutes, httpRoute)
		}

		virtualService.Http = httpRoutes

		newName := namePrefix + "-" + name + "-" + IstioIngressGatewayName
		newNamespace := IstioIngressNamespace

		meta = meta.Clone()
		meta.Name = resource.NewName(newNamespace, newName)
		if meta.Annotations != nil {
			delete(meta.Annotations, kube.IngressClassAnnotation)
		}
		old, f := ingressByHost[host]
		if f {
			vs := old.Item.(*v1alpha3.VirtualService)
			vs.Http = append(vs.Http, httpRoutes...)
		} else {
			ingressByHost[host] = &resource.Entry{
				Metadata: meta,
				Item:     virtualService,
			}
		}
	}

	// Matches * and "/". Currently not supported - would conflict
	// with any other explicit VirtualService.
	if i.Backend != nil {
		scope.Infof("Ignore default wildcard ingress, use VirtualService %s:%s",
			namespace, name)
	}
}

func createStringMatch(s string) *v1alpha3.StringMatch {
	if s == "" {
		return nil
	}

	// Note that this implementation only converts prefix and exact matches, not regexps.

	// Replace e.g. "foo.*" with prefix match
	if strings.HasSuffix(s, ".*") {
		return &v1alpha3.StringMatch{
			MatchType: &v1alpha3.StringMatch_Prefix{Prefix: strings.TrimSuffix(s, ".*")},
		}
	}
	if strings.HasSuffix(s, "/*") {
		return &v1alpha3.StringMatch{
			MatchType: &v1alpha3.StringMatch_Prefix{Prefix: strings.TrimSuffix(s, "/*")},
		}
	}

	// Replace e.g. "foo" with ingressAdapter exact match
	return &v1alpha3.StringMatch{
		MatchType: &v1alpha3.StringMatch_Exact{Exact: s},
	}
}

func ingressBackendToHTTPRoute(backend *ingress.IngressBackend, namespace string, domainSuffix string) *v1alpha3.HTTPRoute {
	if backend == nil {
		return nil
	}

	port := &v1alpha3.PortSelector{
		Port: nil,
	}

	if backend.ServicePort.Type == intstr.Int {
		port.Port = &v1alpha3.PortSelector_Number{
			Number: uint32(backend.ServicePort.IntVal),
		}
	} else {
		// Port names are not allowed in destination rules.
		return nil
	}

	return &v1alpha3.HTTPRoute{
		Route: []*v1alpha3.HTTPRouteDestination{
			{
				Destination: &v1alpha3.Destination{
					Host: fmt.Sprintf("%s.%s.svc.%s", backend.ServiceName, namespace, domainSuffix),
					Port: port,
				},
				Weight: 100,
			},
		},
	}
}
