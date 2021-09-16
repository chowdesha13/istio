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

package extensionproviders

import (
	"fmt"
	"strings"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/host"
)

func LookupCluster(push *model.PushContext, service string, port int) (hostname string, cluster string, err error) {
	if service == "" {
		err = fmt.Errorf("service must not be empty")
		return
	}

	// TODO(yangminzhu): Verify the service and its cluster is supported, e.g. resolution type is not OriginalDst.
	if parts := strings.Split(service, "/"); len(parts) == 2 {
		namespace, name := parts[0], parts[1]
		if svc := push.ServiceIndex().NamespacesForHost(host.Name(name)).Service(namespace); svc != nil {
			hostname = string(svc.ClusterLocal.Hostname)
			cluster = model.BuildSubsetKey(model.TrafficDirectionOutbound, "", svc.ClusterLocal.Hostname, port)
			return
		}
	} else {
		ni := push.ServiceIndex().NamespacesForHost(host.Name(service))
		namespaces := ni.Namespaces(nil)
		// If namespace is omitted, return successfully if there is only one such host name in the service index.
		if len(namespaces) == 1 {
			svc := ni.Service(namespaces[0])
			hostname = string(svc.ClusterLocal.Hostname)
			cluster = model.BuildSubsetKey(model.TrafficDirectionOutbound, "", svc.ClusterLocal.Hostname, port)
			return
		} else if len(namespaces) > 1 {
			err = fmt.Errorf("found %s in multiple namespaces %v, specify the namespace explicitly in "+
				"the format of <Namespace>/<Hostname>", service, namespaces)
			return
		}
	}

	err = fmt.Errorf("could not find service %s in Istio service registry", service)
	return
}
