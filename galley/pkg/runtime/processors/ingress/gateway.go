//  Copyright 2018 Istio Authors
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package ingress

import (
	"istio.io/istio/galley/pkg/runtime/processing"
	"istio.io/istio/galley/pkg/runtime/resource"
)

//  Copyright 2018 Istio Authors
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package direct

import (
"istio.io/istio/galley/pkg/runtime/processing"
"istio.io/istio/galley/pkg/runtime/resource"
)

type gatewayHandler struct {
	v *processing.CachedView
}

func (h *gatewayHandler) Handle(e resource.Event) {
	switch e.Kind {
	case resource.Added, resource.Updated:
		env, err := resource.Envelope(e.Entry)
		if err != nil {
			scope.Errorf("Error enveloping incoming resource(%v): %v", e.Entry.ID, err)
		}
		h.v.Set(e.Entry.ID.FullName, env)

	case resource.Deleted:
		h.v.Remove(e.Entry.ID.FullName)
	}
}
