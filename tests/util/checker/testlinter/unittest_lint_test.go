// Copyright 2018 Istio Authors. All Rights Reserved.
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

package main

import (
	"path/filepath"
	"reflect"
	"testing"

	"istio.io/istio/tests/util/checker"
	"istio.io/istio/tests/util/checker/testlinter/rules"
)

func getAbsPath(path string) string {
	if !filepath.IsAbs(path) {
		path, _ = filepath.Abs(path)
	}
	return path
}

func clearLintRulesList() {
	delete(LintRulesList, UnitTest)
	delete(LintRulesList, IntegTest)
	delete(LintRulesList, E2eTest)
}

func TestUnitTestSkipByIssueRule(t *testing.T) {
	clearLintRulesList()
	LintRulesList[UnitTest] = []checker.Rule{rules.NewSkipByIssue()}

	rpts, _ := getReport([]string{"testdata/"})
	expectedRpts := []string{getAbsPath("testdata/unit_test.go") +
		":9:2:Only t.Skip() is allowed and t.Skip() should contain an url to GitHub issue. (skip_issue)",
		getAbsPath("testdata/unit_test.go") +
			":88:2:Only t.Skip() is allowed and t.Skip() should contain an url to GitHub issue. (skip_issue)",
		getAbsPath("testdata/unit_test.go") +
			":105:2:Only t.Skip() is allowed and t.Skip() should contain an url to GitHub issue. (skip_issue)"}

	if !reflect.DeepEqual(rpts, expectedRpts) {
		t.Errorf("lint reports don't match\nReceived: %v\nExpected: %v", rpts, expectedRpts)
	}
}

func TestUnitTestNoShortRule(t *testing.T) {
	clearLintRulesList()
	LintRulesList[UnitTest] = []checker.Rule{rules.NewNoShort()}

	rpts, _ := getReport([]string{"testdata/"})
	expectedRpts := []string{getAbsPath("testdata/unit_test.go") + ":32:5:testing.Short() is disallowed. (no_short)",
		getAbsPath("testdata/unit_test.go") + ":93:5:testing.Short() is disallowed. (no_short)",
		getAbsPath("testdata/unit_test.go") + ":110:5:testing.Short() is disallowed. (no_short)"}

	if !reflect.DeepEqual(rpts, expectedRpts) {
		t.Errorf("lint reports don't match\nReceived: %v\nExpected: %v", rpts, expectedRpts)
	}
}

func TestUnitTestNoSleepRule(t *testing.T) {
	clearLintRulesList()
	LintRulesList[UnitTest] = []checker.Rule{rules.NewNoSleep()}

	rpts, _ := getReport([]string{"testdata/"})
	expectedRpts := []string{getAbsPath("testdata/unit_test.go") + ":49:2:time.Sleep() is disallowed. (no_sleep)",
		getAbsPath("testdata/unit_test.go") + ":99:2:time.Sleep() is disallowed. (no_sleep)",
		getAbsPath("testdata/unit_test.go") + ":116:2:time.Sleep() is disallowed. (no_sleep)"}

	if !reflect.DeepEqual(rpts, expectedRpts) {
		t.Errorf("lint reports don't match\nReceived: %v\nExpected: %v", rpts, expectedRpts)
	}
}

func TestUnitTestNoGoroutineRule(t *testing.T) {
	clearLintRulesList()
	LintRulesList[UnitTest] = []checker.Rule{rules.NewNoGoroutine()}

	rpts, _ := getReport([]string{"testdata/"})
	expectedRpts := []string{getAbsPath("testdata/unit_test.go") + ":57:2:goroutine is disallowed. (no_goroutine)"}

	if !reflect.DeepEqual(rpts, expectedRpts) {
		t.Errorf("lint reports don't match\nReceived: %v\nExpected: %v", rpts, expectedRpts)
	}
}

func TestUnitTestGlobalWhitelistRule(t *testing.T) {
	clearLintRulesList()
	LintRulesList[UnitTest] = []checker.Rule{
		rules.NewSkipByIssue(),
		rules.NewNoGoroutine(),
		rules.NewNoSleep(),
		rules.NewNoShort()}

	rpts, _ := getReport([]string{"testdata/unit_whitelist_test.go"})
	expectedRpts := []string{}

	if !reflect.DeepEqual(rpts, expectedRpts) {
		t.Errorf("lint reports don't match\nReceived: %v\nExpected: %v", rpts, expectedRpts)
	}
}
