// Copyright 2018 Istio Authors
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

package configdump

import (
	"fmt"

	proto "github.com/gogo/protobuf/types"
)

// See https://www.envoyproxy.io/docs/envoy/latest/api-v2/admin/v2alpha/config_dump.proto
const (
	// BootstrapConfigDumpTypeURL is the unique type indicator for the Bootstrap section of the config dump
	BootstrapConfigDumpTypeURL = "type.googleapis.com/envoy.admin.v2alpha.BootstrapConfigDump"

	// ListenersConfigDumpTypeURL is the unique identifier the Listeners section of the config dump
	ListenersConfigDumpTypeURL = "type.googleapis.com/envoy.admin.v2alpha.ListenersConfigDump"

	// ClustersConfigDumpTypeURL is the unique identifier the Clusters section of the config dump
	ClustersConfigDumpTypeURL = "type.googleapis.com/envoy.admin.v2alpha.ClustersConfigDump"

	// BootstrapConfigDumpTypeURL is the unique identifier the Routes section of the config dump
	RoutesConfigDumpTypeURL = "type.googleapis.com/envoy.admin.v2alpha.RoutesConfigDump"
)

// configDumpSection takes a TypeURL and returns the types.Any from the config dump corresponding to that URL
func (w *Wrapper) configDumpSection(sectionTypeURL string) (proto.Any, error) {
	var dumpAny proto.Any
	for _, conf := range w.Configs {
		if conf.TypeUrl == sectionTypeURL {
			dumpAny = *conf
		}
	}
	if dumpAny.TypeUrl == "" {
		return proto.Any{}, fmt.Errorf("config dump has no route %s", sectionTypeURL)
	}

	return dumpAny, nil
}
