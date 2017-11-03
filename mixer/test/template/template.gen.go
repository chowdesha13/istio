// Copyright 2017 Istio Authors
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

// THIS FILE IS AUTOMATICALLY GENERATED.

package template

import (
	"context"
	"errors"
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/glog"

	"istio.io/api/mixer/v1/config/descriptor"
	adptTmpl "istio.io/api/mixer/v1/template"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/pkg/attribute"
	"istio.io/istio/mixer/pkg/expr"
	"istio.io/istio/mixer/pkg/template"

	"istio.io/istio/mixer/test/template/report"
)

const emptyQuotes = "\"\""

var (
	SupportedTmplInfo = map[string]template.Info{

		samplereport.TemplateName: {
			Name:               samplereport.TemplateName,
			Impl:               "samplereport",
			CtrCfg:             &samplereport.InstanceParam{},
			Variety:            adptTmpl.TEMPLATE_VARIETY_REPORT,
			BldrInterfaceName:  samplereport.TemplateName + "." + "HandlerBuilder",
			HndlrInterfaceName: samplereport.TemplateName + "." + "Handler",
			BuilderSupportsTemplate: func(hndlrBuilder adapter.HandlerBuilder) bool {
				_, ok := hndlrBuilder.(samplereport.HandlerBuilder)
				return ok
			},
			HandlerSupportsTemplate: func(hndlr adapter.Handler) bool {
				_, ok := hndlr.(samplereport.Handler)
				return ok
			},
			InferType: func(cp proto.Message, tEvalFn template.TypeEvalFn) (proto.Message, error) {
				var err error = nil
				cpb := cp.(*samplereport.InstanceParam)
				infrdType := &samplereport.Type{}

				if cpb.Value == "" || cpb.Value == emptyQuotes {
					return nil, errors.New("expression for field Value cannot be empty")
				}
				if infrdType.Value, err = tEvalFn(cpb.Value); err != nil {
					return nil, err
				}

				infrdType.Dimensions = make(map[string]istio_mixer_v1_config_descriptor.ValueType, len(cpb.Dimensions))
				for k, v := range cpb.Dimensions {
					if infrdType.Dimensions[k], err = tEvalFn(v); err != nil {
						return nil, err
					}
				}

				_ = cpb
				return infrdType, err
			},
			SetType: func(types map[string]proto.Message, builder adapter.HandlerBuilder) {
				// Mixer framework should have ensured the type safety.
				castedBuilder := builder.(samplereport.HandlerBuilder)
				castedTypes := make(map[string]*samplereport.Type, len(types))
				for k, v := range types {
					// Mixer framework should have ensured the type safety.
					v1 := v.(*samplereport.Type)
					castedTypes[k] = v1
				}
				castedBuilder.SetSampleReportTypes(castedTypes)
			},

			ProcessReport: func(ctx context.Context, insts map[string]proto.Message, attrs attribute.Bag, mapper expr.Evaluator, handler adapter.Handler) error {
				var instances []*samplereport.Instance
				for name, inst := range insts {
					md := inst.(*samplereport.InstanceParam)

					Value, err := mapper.Eval(md.Value, attrs)

					if err != nil {
						msg := fmt.Sprintf("failed to eval Value for instance '%s': %v", name, err)
						glog.Error(msg)
						return errors.New(msg)
					}

					Dimensions, err := template.EvalAll(md.Dimensions, attrs, mapper)

					if err != nil {
						msg := fmt.Sprintf("failed to eval Dimensions for instance '%s': %v", name, err)
						glog.Error(msg)
						return errors.New(msg)
					}

					instances = append(instances, &samplereport.Instance{
						Name: name,

						Value: Value,

						Dimensions: Dimensions,
					})
					_ = md
				}

				if err := handler.(samplereport.Handler).HandleSampleReport(ctx, instances); err != nil {
					return fmt.Errorf("failed to report all values: %v", err)
				}
				return nil
			},
		},
	}
)
