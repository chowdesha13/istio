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

package istio_mixer_adapter_quota

import (
	_ "github.com/gogo/protobuf/types"

	_ "istio.io/api/mixer/v1/config/descriptor"
	_ "istio.io/mixer/pkg/adapter/template"
)

type Instance struct {
	Name string

	Dimensions map[string]interface{}
}

type QuotaProcessor interface {
	ConfigureQuota(types map[string]*Type) error
	ReportQuota(instances []*Instance) error
}
