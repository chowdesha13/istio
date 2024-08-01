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

package validate

import (
	"errors"
	"fmt"
	"reflect"

	"google.golang.org/protobuf/types/known/structpb"

	"istio.io/istio/operator/pkg/apis/istio/v1alpha1"
	operator_v1alpha1 "istio.io/istio/operator/pkg/apis/istio/v1alpha1"
	"istio.io/istio/operator/pkg/tpath"
	"istio.io/istio/operator/pkg/util"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/util/protomarshal"
)

// CheckIstioOperator validates the operator CR.
func CheckIstioOperator(iop *operator_v1alpha1.IstioOperator) error {
	if iop == nil {
		return nil
	}

	errs := CheckIstioOperatorSpec(iop.Spec)
	return errs.ToError()
}

// CheckIstioOperatorSpec validates the values in the given Installer spec, using the field map DefaultValidations to
// call the appropriate validation function. checkRequiredFields determines whether missing mandatory fields generate
// errors.
func CheckIstioOperatorSpec(is *v1alpha1.IstioOperatorSpec) util.Errors {
	if is == nil {
		return nil
	}
	val := is.Values
	var errs util.Errors

	run := func(v any, f ValidatorFunc, p string) {
		if !reflect.ValueOf(v).IsZero() {
			errs = util.AppendErrs(errs, f(util.PathFromString(p), v))
		}
	}
	runValues := func(ff ValidatorFunc, p string) {
		v, f, _ := tpath.GetFromStructPath(val, p)
		if f {
			errs = util.AppendErrs(errs, ff(util.PathFromString(p), v))
		}
	}
	runValues(validateIPRangesOrStar, "global.proxy.includeIPRanges")
	runValues(validateIPRangesOrStar, "global.proxy.excludeIPRanges")
	runValues(validateStringList(validatePortNumberString), "global.proxy.includeInboundPorts")
	runValues(validateStringList(validatePortNumberString), "global.proxy.excludeInboundPorts")
	runValues(validateMeshConfig, "meshConfig")

	run(is.GetMeshConfig(), validateMeshConfig, "meshConfig")
	run(is.GetHub(), validateHub, "hub")
	run(is.GetTag(), validateTag, "tag")
	run(is.GetRevision(), validateRevision, "revision")
	run(is.GetComponents().GetIngressGateways(), validateGatewayName, "components.ingressGateways")
	run(is.GetComponents().GetEgressGateways(), validateGatewayName, "components.egressGateways")
	return errs
}

func validateMeshConfig(path util.Path, root any) util.Errors {
	vs, err := util.ToYAMLGeneric(root)
	if err != nil {
		return util.Errors{err}
	}
	// ApplyMeshConfigDefaults allows unknown fields, so we first check for unknown fields
	if err := protomarshal.ApplyYAMLStrict(string(vs), mesh.DefaultMeshConfig()); err != nil {
		return util.Errors{fmt.Errorf("failed to unmarshall mesh config: %v", err)}
	}
	// This method will also perform validation automatically
	if _, validErr := mesh.ApplyMeshConfigDefaults(string(vs)); validErr != nil {
		return util.Errors{validErr}
	}
	return nil
}

func validateHub(path util.Path, val any) util.Errors {
	if val == "" {
		return nil
	}
	return validateWithRegex(path, val, ReferenceRegexp)
}

func validateTag(path util.Path, val any) util.Errors {
	return validateWithRegex(path, val.(*structpb.Value).GetStringValue(), TagRegexp)
}

func validateRevision(_ util.Path, val any) util.Errors {
	if val == "" {
		return nil
	}
	if !labels.IsDNS1123Label(val.(string)) {
		err := fmt.Errorf("invalid revision specified: %s", val.(string))
		return util.Errors{err}
	}
	return nil
}

func validateGatewayName(path util.Path, val any) (errs util.Errors) {
	v := val.([]*v1alpha1.GatewaySpec)
	for _, n := range v {
		if n == nil {
			errs = append(errs, util.NewErrs(errors.New("badly formatted gateway configuration")))
		} else {
			errs = append(errs, validateWithRegex(path, n.Name, ObjectNameRegexp)...)
		}
	}
	return
}
