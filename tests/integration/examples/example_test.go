// Copyright 2019 Istio Authors
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

package examples

import (
	"testing"

	"istio.io/istio/tests/integration/examples/mycomponent"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/environment"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/label"
)

var (
	i  istio.Instance
	mc mycomponent.Instance
)

// TestMain needs to be implemented and tests should be executed through framework.TestSuite
func TestMain(m *testing.M) {
	// Start your call with framework.NewSuite, which creates a new framework.Suite instance that you can configure
	// before starting tests.
	framework.
		NewSuite("galley_conversion", m).

		// Labels that apply to the whole suite can be specified here.
		Label(label.Presubmit).

		// You can restrict the execution of the whole suite to a particular environment. This restricts execution
		// to the native environment.
		RequireEnvironment(environment.Native).

		// You can specify multiple setup functions that will be run as part of suite setup. setupFn will always be called.
		Setup(mysetup).

		// The following two setup methods will run conditionally, depending on the environment.
		EnvSetup(environment.Native, setupNative).
		EnvSetup(environment.Kube, setupKube).

		// The following is an example of how to deploy Istio on Kubernetes, as part of the suite setup.
		// (Since this is an example, this will not execute as the RequireEnvironment call above will stop execution on Kube.)
		Setup(istio.SetupOnKube(&i, nil)).

		// Finally execute the test suite
		Run()
}

func mysetup(c framework.SuiteContext) error {
	// this function will be called as part of suite setup. You can do one-time setup here.
	// returning an error from here will cause the suite to fail all-together.

	// You can use the suite context to perform various operations. For example you can create folders or temp
	// folders as part of your operations.
	_, err := c.CreateDirectory("example_foo")
	if err != nil {
		return err
	}

	// As part of your setup, you can create suite-level resources and track them. The "mc" resource will be
	// active as long as the suit is alive, as it is created within the context of suite-level setup.
	mc, err = mycomponent.New(c, mycomponent.Config{})
	if err != nil {
		return err
	}

	return nil
}

func setupNative(_ framework.SuiteContext) error {
	return nil
}

func setupKube(_ framework.SuiteContext) error {
	return nil
}

func TestStyle1(t *testing.T) {
	// Ideally, run your test code in a lambda. This ensures that the resources allocated in the context of the test
	// is cleaned up correctly.
	framework.Run(t, func(ctx framework.TestContext) {
		// You can use the framework.TestContext methods directly to interact with the framework.
		ctx.CreateDirectoryOrFail(t, "boo")

		// You can allocate components at the test level as well. mc2's life will be scoped to this lambda call.
		mc2 := mycomponent.NewOrFail(t, ctx, mycomponent.Config{DoStuffElegantly: true})
		_ = mc2

		// Ignore these, these are here to appease the linter
		_ = mc
		_ = i
	})
}

func TestStyle2(t *testing.T) {
	// You can specify additional constraints using the more verbose form
	framework.NewTest(t).
		Label(label.Postsubmit).
		RequiresEnvironment(environment.Kube).
		Run(func(ctx framework.TestContext) {

			// This tests will run only on Kube environment as Presubmit. Note that the suite level requirements will
			// always have precedence.
			//
			// The labels at the suite and test label will be cumulative. For example, this suite is tagged with Presubmit
			// and the test is tagged with Postsubmit. In aggregate, this test has both Presubmit and Postsubmit labels.
		})
}
