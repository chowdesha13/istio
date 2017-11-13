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

package runtime

import (
	"context"

	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/pkg/attribute"
)

func newContextWithRequestData(ctx context.Context, requestBag attribute.Bag, destinationServiceAttr string) context.Context {
	reqData := &adapter.RequestData{}
	// fill the destination information
	if destSrvc, found := requestBag.Get(destinationServiceAttr); found {
		reqData.DestinationService = adapter.Service{FullName: destSrvc.(string)}
	}

	return adapter.NewContextWithRequestData(ctx, reqData)
}
