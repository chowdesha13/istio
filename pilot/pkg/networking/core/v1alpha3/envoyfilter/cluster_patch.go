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

package envoyfilter

import (
	"fmt"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/proto"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pilot/pkg/util/runtime"
	"istio.io/istio/pkg/config/host"
	"istio.io/istio/pkg/proto/merge"
	"istio.io/pkg/log"
)

// ApplyClusterMerge processes the MERGE operation and merges the supplied configuration to the matched clusters.
func ApplyClusterMerge(pctx networking.EnvoyFilter_PatchContext, efw *model.EnvoyFilterWrapper,
	c *cluster.Cluster, hosts []host.Name,
) (out *cluster.Cluster) {
	defer runtime.HandleCrash(runtime.LogPanic, func(any) {
		log.Errorf("clusters patch %s/%s caused panic, so the patches did not take effect", efw.Namespace, efw.Name)
		IncrementEnvoyFilterErrorMetric(Cluster)
	})
	// In case the patches cause panic, use the clusters generated before to reduce the influence.
	out = c
	if efw == nil {
		return
	}
	for _, cp := range efw.Patches[networking.EnvoyFilter_CLUSTER] {
		applied := false
		if cp.Operation != networking.EnvoyFilter_Patch_MERGE {
			IncrementEnvoyFilterMetric(cp.Key(), Cluster, applied)
			continue
		}
		if commonConditionMatch(pctx, cp) && clusterMatch(c, cp, hosts) {
			// backup the Cluster in case mergeTransportSocketCluster modifies it
			cpValueBkp := proto.Clone(cp.Value)

			err := mergeTransportSocketCluster(c, cp)
			if err != nil {
				log.Debugf("Merge of transport socket failed for cluster: %v", err)
				continue
			}
			applied = true
			merge.Merge(c, cp.Value)

			// restore untouched copy of the Cluster for use in next iteration
			cp.Value = cpValueBkp
		}
		IncrementEnvoyFilterMetric(cp.Key(), Cluster, applied)
	}
	return c
}

func patchTransportSocket(ts *core.TransportSocket, patchTS *core.TransportSocket) (err error) {
	dstCluster := ts.GetTypedConfig()
	srcPatch := patchTS.GetTypedConfig()

	if dstCluster != nil && srcPatch != nil {

		retVal, errMerge := util.MergeAnyWithAny(dstCluster, srcPatch)
		if errMerge != nil {
			return fmt.Errorf("function MergeAnyWithAny failed for ApplyClusterMerge: %v", errMerge)
		}

		// Merge the above result with the whole cluster
		merge.Merge(dstCluster, retVal)
	}
	return nil
}

// Applies special case for patching Transport Socket and Transport Socket Matches
// and removes used TS and TSM structs from source patch
func mergeTransportSocketCluster(c *cluster.Cluster, cp *model.EnvoyFilterConfigPatchWrapper) (err error) {
	cpValueCast, okCpCast := (cp.Value).(*cluster.Cluster)
	if !okCpCast {
		return fmt.Errorf("cast of cp.Value failed: %v", okCpCast)
	}

	// First merge transport socket matches with the same name
	if (len(c.GetTransportSocketMatches())) > 0 && (len(cpValueCast.GetTransportSocketMatches()) > 0) {
		// List what will hold not used (not applied) TransportSocketMatches to use with direct merging later
		newPatchTsms := make([]*cluster.Cluster_TransportSocketMatch, 0, len(c.GetTransportSocketMatches()))

		for _, cpTsm := range cpValueCast.GetTransportSocketMatches() {
			if cpTsm.GetName() == "" || (cpTsm.GetTransportSocket() == nil && cpTsm.GetMatch() == nil) {
				// Don't try merging if TransportSocketMatches' TransportSocket and Match are both null or
				// name is empty - name is used to match TransportSockets in patch to the one in live Cluster and
				// if TransportSocket and Match are both null there's nothing to patch
				newPatchTsms = append(newPatchTsms, cpTsm)
				continue
			}

			tsmMerged := false

			for _, tsm := range c.GetTransportSocketMatches() {
				if tsm.GetName() != cpTsm.GetName() {
					// Skip unmatched names
					continue
				}

				if cpTsm.GetMatch() != nil {
					// Replace Match if defined in patch
					tsm.Match = cpTsm.Match
					tsmMerged = true
				}

				// Merge TransportSockets
				if tsm.GetTransportSocket() != nil && cpTsm.GetTransportSocket() != nil {
					if cpTsm.GetTransportSocket().Name == tsm.GetTransportSocket().Name {
						// Merge when it's the same type
						err := patchTransportSocket(tsm.GetTransportSocket(), cpTsm.GetTransportSocket())
						if err != nil {
							return err
						}
					} else {
						// Replace when type mismatch
						tsm.TransportSocket = cpTsm.TransportSocket
					}
					tsmMerged = true
				}
			}

			if !tsmMerged {
				newPatchTsms = append(newPatchTsms, cpTsm)
			}
		}

		if len(newPatchTsms) != len(cpValueCast.TransportSocketMatches) {
			cpValueCast.TransportSocket = nil
		}
		cpValueCast.TransportSocketMatches = newPatchTsms
	}

	// Check if cluster patch has a transport socket.
	if cpValueCast.GetTransportSocket() == nil {
		return nil
	}
	var tsmPatch *core.TransportSocket

	// Check if the transport socket matches with any cluster transport socket matches.
	if len(c.GetTransportSocketMatches()) > 0 {
		for _, tsm := range c.GetTransportSocketMatches() {
			if tsm.GetTransportSocket() != nil && cpValueCast.GetTransportSocket().Name == tsm.GetTransportSocket().Name {
				tsmPatch = tsm.GetTransportSocket()
				break
			}
		}
		if tsmPatch == nil {
			// If we merged we would get both a transport_socket and transport_socket_matches which is not valid
			// Drop the TS from the patch so that the outer function does not try to merge it again
			cpValueCast.TransportSocket = nil
			return nil
		}
	} else if c.GetTransportSocket() != nil {
		if cpValueCast.GetTransportSocket().Name == c.GetTransportSocket().Name {
			tsmPatch = c.GetTransportSocket()
		}
	}
	// This means either there is a name mismatch or cluster does not have transport socket matches/transport socket.
	// We cannot do a deep merge. Instead, just replace the transport socket
	if tsmPatch == nil {
		c.TransportSocket = cpValueCast.TransportSocket
	} else {
		// Merge the patch and the cluster at a lower level
		err := patchTransportSocket(tsmPatch, cpValueCast.GetTransportSocket())
		if err != nil {
			return err
		}
	}
	cpValueCast.TransportSocket = nil
	return nil
}

// ShouldKeepCluster checks if there is a REMOVE patch on the cluster, returns false if there is one so that it is removed.
func ShouldKeepCluster(pctx networking.EnvoyFilter_PatchContext, efw *model.EnvoyFilterWrapper, c *cluster.Cluster, hosts []host.Name) bool {
	if efw == nil {
		return true
	}
	for _, cp := range efw.Patches[networking.EnvoyFilter_CLUSTER] {
		if cp.Operation != networking.EnvoyFilter_Patch_REMOVE {
			continue
		}
		if commonConditionMatch(pctx, cp) && clusterMatch(c, cp, hosts) {
			return false
		}
	}
	return true
}

// InsertedClusters collects all clusters that are added via ADD operation and match the patch context.
func InsertedClusters(pctx networking.EnvoyFilter_PatchContext, efw *model.EnvoyFilterWrapper) []*cluster.Cluster {
	if efw == nil {
		return nil
	}
	var result []*cluster.Cluster
	// Add cluster if the operation is add, and patch context matches
	for _, cp := range efw.Patches[networking.EnvoyFilter_CLUSTER] {
		if cp.Operation == networking.EnvoyFilter_Patch_ADD {
			// If cluster ADD patch does not specify a patch context, only add for sidecar outbound and gateway.
			if cp.Match.Context == networking.EnvoyFilter_ANY && pctx != networking.EnvoyFilter_SIDECAR_OUTBOUND &&
				pctx != networking.EnvoyFilter_GATEWAY {
				continue
			}
			if commonConditionMatch(pctx, cp) {
				result = append(result, proto.Clone(cp.Value).(*cluster.Cluster))
			}
		}
	}
	return result
}

func clusterMatch(cluster *cluster.Cluster, cp *model.EnvoyFilterConfigPatchWrapper, hosts []host.Name) bool {
	cMatch := cp.Match.GetCluster()
	if cMatch == nil {
		return true
	}

	if cMatch.Name != "" {
		return cMatch.Name == cluster.Name
	}

	direction, subset, hostname, port := model.ParseSubsetKey(cluster.Name)

	hostMatches := []host.Name{hostname}
	// For inbound clusters, host parsed from subset key will be empty. Use the passed in service name.
	if direction == model.TrafficDirectionInbound && len(hosts) > 0 {
		hostMatches = hosts
	}

	if cMatch.Subset != "" && cMatch.Subset != subset {
		return false
	}

	if cMatch.Service != "" && !hostContains(hostMatches, host.Name(cMatch.Service)) {
		return false
	}

	// FIXME: Ports on a cluster can be 0. the API only takes uint32 for ports
	// We should either make that field in API as a wrapper type or switch to int
	if cMatch.PortNumber != 0 && int(cMatch.PortNumber) != port {
		return false
	}
	return true
}

func hostContains(hosts []host.Name, service host.Name) bool {
	for _, h := range hosts {
		if h == service {
			return true
		}
	}
	return false
}
