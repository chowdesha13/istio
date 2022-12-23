//go:build integ
// +build integ

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

package helmupgrade

import (
	"fmt"
	"strings"
	"testing"

	"istio.io/istio/pkg/test/framework"
)

const (
	previousSupportedVersion = "1.16.0"
	nMinusTwoVersion         = "1.15.0"
)

// TestDefaultInPlaceUpgradeFromPreviousMinorRelease tests Istio upgrade using Helm with default options for Istio 1.(n-1)
func TestDefaultInPlaceUpgradeFromPreviousMinorRelease(t *testing.T) {
	framework.
		NewTest(t).
		Features("installation.helm.default.upgrade").
		Run(performInPlaceUpgradeFunc(previousSupportedVersion))
}

// TestCanaryUpgradeFromPreviousMinorRelease tests Istio upgrade using Helm with default options for Istio 1.(n-1)
func TestCanaryUpgradeFromPreviousMinorRelease(t *testing.T) {
	framework.
		NewTest(t).
		Features("installation.helm.default.upgrade").
		Run(performCanaryUpgradeFunc(previousSupportedVersion))
}

// TestCanaryUpgradeFromTwoMinorRelease tests Istio upgrade using Helm with default options for Istio 1.(n-2)
func TestCanaryUpgradeFromTwoMinorRelease(t *testing.T) {
	framework.
		NewTest(t).
		Features("installation.helm.default.upgrade").
		Run(performCanaryUpgradeFunc(nMinusTwoVersion))
}

// TestStableRevisionLabelsUpgradeFromPreviousMinorRelease tests Istio upgrade using Helm with default options for Istio 1.(n-1)
func TestStableRevisionLabelsUpgradeFromPreviousMinorRelease(t *testing.T) {
	previousRevision := strings.ReplaceAll(previousSupportedVersion, ".", "-")
	framework.
		NewTest(t).
		Features("installation.helm.default.upgrade").
		Run(performRevisionTagsUpgradeFunc(previousSupportedVersion,
			fmt.Sprintf("istio-validator-%s-istio-system", previousRevision), true))
}

// TestStableRevisionLabelsUpgradeFromTwoMinorRelease tests Istio upgrade using Helm with default options for Istio 1.(n-2)
func TestStableRevisionLabelsUpgradeFromTwoMinorRelease(t *testing.T) {
	framework.
		NewTest(t).
		Features("installation.helm.default.upgrade").
		Run(performRevisionTagsUpgradeFunc(nMinusTwoVersion, "istiod-istio-system", false))
}
