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

package ambient

type NodeType = string

const (
	LabelStatus = "istio.io/ambient-status"
	TypeEnabled = "enabled"
	// LabelType == "workload" -> intercept into ztunnel
	// TODO this could be an annotation – eventually move it into api repo
	LabelType = "ambient-type"

	TypeWorkload NodeType = "workload"
	TypeNone     NodeType = "none"
	TypeWaypoint NodeType = "waypoint"
)
