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

package rt

import (
	"fmt"
	"reflect"

	"github.com/gogo/protobuf/proto"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/tools/cache"
)

func (p *Provider) initKnownAdapters() {
	runtimeScheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(runtimeScheme)
	deserializer := codecs.UniversalDeserializer()

	p.known = map[string]*Adapter{
		asTypesKey("", "Service"): {
			extractObject: defaultExtractObject,
			extractResource: func(o interface{}) (proto.Message, error) {
				if obj, ok := o.(*v1.Service); ok {
					return &obj.Spec, nil
				}
				return nil, fmt.Errorf("unable to convert to v1.Service: %v", reflect.TypeOf(o))
			},
			newInformer: func() (cache.SharedIndexInformer, error) {
				informer, err := p.sharedInformerFactory()
				if err != nil {
					return nil, err
				}

				return informer.Core().V1().Services().Informer(), nil
			},
			parseJSON: func(input []byte) (interface{}, error) {
				out := &v1.Service{}
				if _, _, err := deserializer.Decode(input, nil, out); err != nil {
					return nil, err
				}
				return out, nil
			},
			isBuiltIn: true,
		},

		asTypesKey("", "Namespace"): {
			extractObject: defaultExtractObject,
			extractResource: func(o interface{}) (proto.Message, error) {
				if obj, ok := o.(*v1.Namespace); ok {
					return &obj.Spec, nil
				}
				return nil, fmt.Errorf("unable to convert to v1.Namespace: %v", reflect.TypeOf(o))
			},
			newInformer: func() (cache.SharedIndexInformer, error) {
				informer, err := p.sharedInformerFactory()
				if err != nil {
					return nil, err
				}

				return informer.Core().V1().Namespaces().Informer(), nil
			},
			parseJSON: func(input []byte) (interface{}, error) {
				out := &v1.Namespace{}
				if _, _, err := deserializer.Decode(input, nil, out); err != nil {
					return nil, err
				}
				return out, nil
			},
			isBuiltIn: true,
		},

		asTypesKey("", "Node"): {
			extractObject: defaultExtractObject,
			extractResource: func(o interface{}) (proto.Message, error) {
				if obj, ok := o.(*v1.Node); ok {
					return &obj.Spec, nil
				}
				return nil, fmt.Errorf("unable to convert to v1.Node: %v", reflect.TypeOf(o))
			},
			newInformer: func() (cache.SharedIndexInformer, error) {
				informer, err := p.sharedInformerFactory()
				if err != nil {
					return nil, err
				}

				return informer.Core().V1().Nodes().Informer(), nil
			},
			parseJSON: func(input []byte) (interface{}, error) {
				out := &v1.Node{}
				if _, _, err := deserializer.Decode(input, nil, out); err != nil {
					return nil, err
				}
				return out, nil
			},
			isBuiltIn: true,
		},

		asTypesKey("", "Pod"): {
			extractObject: defaultExtractObject,
			extractResource: func(o interface{}) (proto.Message, error) {
				if obj, ok := o.(*v1.Pod); ok {
					return obj, nil
				}
				return nil, fmt.Errorf("unable to convert to v1.Pod: %v", reflect.TypeOf(o))
			},
			newInformer: func() (cache.SharedIndexInformer, error) {
				informer, err := p.sharedInformerFactory()
				if err != nil {
					return nil, err
				}

				return informer.Core().V1().Pods().Informer(), nil
			},
			parseJSON: func(input []byte) (interface{}, error) {
				out := &v1.Pod{}
				if _, _, err := deserializer.Decode(input, nil, out); err != nil {
					return nil, err
				}
				return out, nil
			},
			isBuiltIn: true,
		},

		asTypesKey("", "Endpoints"): {
			extractObject: defaultExtractObject,
			extractResource: func(o interface{}) (proto.Message, error) {
				// TODO(nmittler): This copies ObjectMeta since Endpoints have no spec.
				if obj, ok := o.(*v1.Endpoints); ok {
					return obj, nil
				}
				return nil, fmt.Errorf("unable to convert to v1.Endpoints: %v", reflect.TypeOf(o))
			},
			newInformer: func() (cache.SharedIndexInformer, error) {
				informer, err := p.sharedInformerFactory()
				if err != nil {
					return nil, err
				}

				return informer.Core().V1().Services().Informer(), nil
			},
			parseJSON: func(input []byte) (interface{}, error) {
				out := &v1.Endpoints{}
				if _, _, err := deserializer.Decode(input, nil, out); err != nil {
					return nil, err
				}
				return out, nil
			},
			isBuiltIn: true,
		},
		asTypesKey("extensions", "Ingress"): {
			extractObject: defaultExtractObject,
			extractResource: func(o interface{}) (proto.Message, error) {
				if obj, ok := o.(*v1beta1.Ingress); ok {
					return &obj.Spec, nil
				}
				return nil, fmt.Errorf("unable to convert to v1beta1.Ingress: %v", reflect.TypeOf(o))
			},
			newInformer: func() (cache.SharedIndexInformer, error) {
				informer, err := p.sharedInformerFactory()
				if err != nil {
					return nil, err
				}

				return informer.Extensions().V1beta1().Ingresses().Informer(), nil
			},
			parseJSON: func(input []byte) (interface{}, error) {
				out := &v1beta1.Ingress{}
				if _, _, err := deserializer.Decode(input, nil, out); err != nil {
					return nil, err
				}
				return out, nil
			},
			isBuiltIn: true,
		},
	}
}

func asTypesKey(group, kind string) string {
	if group == "" {
		return kind
	}
	return fmt.Sprintf("%s/%s", group, kind)
}

func defaultExtractObject(o interface{}) metav1.Object {
	if obj, ok := o.(metav1.Object); ok {
		return obj
	}
	return nil
}
