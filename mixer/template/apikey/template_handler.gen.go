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

package apikey

import (
	"context"
	"time"

	"istio.io/istio/mixer/pkg/adapter"
)

// The `apikey` template represents a single API key, which is used for authorization checks.
//
// Example config:
//
// ```yaml
// apiVersion: "config.istio.io/v1alpha2"
// kind: apikey
// metadata:
//   name: validate-apikey
//   namespace: istio-system
// spec:
//   api: api.service | ""
//   api_version: api.version | ""
//   api_operation: api.operation | ""
//   api_key: api.key | ""
//   timestamp: request.time
// ```

// Fully qualified name of the template
const TemplateName = "apikey"

// Instance is constructed by Mixer for the 'apikey' template.
//
// The `apikey` template represents a single API key, used to authorize API calls.
type Instance struct {
	// Name of the instance as specified in configuration.
	Name string

	// The API being called (api.service).
	Api string

	// The version of the API (api.version).
	ApiVersion string

	// The API operation is being called.
	ApiOperation string

	// API key used in API call.
	ApiKey string

	// Timestamp of API call.
	Timestamp time.Time
}

// HandlerBuilder must be implemented by adapters if they want to
// process data associated with the 'apikey' template.
//
// Mixer uses this interface to call into the adapter at configuration time to configure
// it with adapter-specific configuration as well as all template-specific type information.
type HandlerBuilder interface {
	adapter.HandlerBuilder

	// SetApiKeyTypes is invoked by Mixer to pass the template-specific Type information for instances that an adapter
	// may receive at runtime. The type information describes the shape of the instance.
	SetApiKeyTypes(map[string]*Type /*Instance name -> Type*/)
}

// Handler must be implemented by adapter code if it wants to
// process data associated with the 'apikey' template.
//
// Mixer uses this interface to call into the adapter at request time in order to dispatch
// created instances to the adapter. Adapters take the incoming instances and do what they
// need to achieve their primary function.
//
// The name of each instance can be used as a key into the Type map supplied to the adapter
// at configuration time via the method 'SetApiKeyTypes'.
// These Type associated with an instance describes the shape of the instance
type Handler interface {
	adapter.Handler

	// HandleApiKey is called by Mixer at request time to deliver instances to
	// to an adapter.
	HandleApiKey(context.Context, *Instance) (adapter.CheckResult, error)
}
