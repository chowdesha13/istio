/*
 Copyright Istio Authors

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package local

import (
	"istio.io/istio/pkg/config/analysis/diag"
)

const (
	meshConfigMapKey   = "mesh"
	meshConfigMapName  = "istio"
	meshNetworksMapKey = "meshNetworks"
)

// AnalysisResult represents the returnable results of an analysis execution
type AnalysisResult struct {
	Messages          diag.Messages
	ExecutedAnalyzers []string
}
