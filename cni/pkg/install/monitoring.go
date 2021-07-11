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

package install

import "istio.io/pkg/monitoring"

var (
	resultLabel                   = monitoring.MustCreateLabel("result")
	resultSuccess                 = "SUCCESS"
	resultCopyBinariesFailure     = "COPY_BINARIES_FAILURE"
	resultReadSAFailure           = "READ_SERVICE_ACCOUNT_FAILURE"
	resultCreateKubeConfigFailure = "CREATE_KUBECONFIG_FAILURE"
	resultCreateCNIConfigFailure  = "CREATE_KUBECONFIG_FAILURE"

	stateLabel   = monitoring.MustCreateLabel("state")
	stateReady   = "READY"
	stateUnready = "UNREADY"

	cniInstalls = monitoring.NewSum(
		"istio_cni_installs_total",
		"Total number of CNI plugins installed by the ßIstio CNI installer",
		monitoring.WithLabels(resultLabel),
	)

	installState = monitoring.NewGauge(
		"istio_cni_install_state",
		"Installation state of CNI plugin, one of [READY, UNREADY]",
		monitoring.WithLabels(stateLabel),
	)
)

func init() {
	monitoring.MustRegister(cniInstalls)
	monitoring.MustRegister(installState)
}
