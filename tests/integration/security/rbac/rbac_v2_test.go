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

package rbac

import (
	"testing"
	"time"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/apps"
	"istio.io/istio/pkg/test/framework/components/environment"
	"istio.io/istio/pkg/test/framework/components/environment/kube"
	"istio.io/istio/pkg/test/framework/components/galley"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/components/pilot"
	"istio.io/istio/pkg/test/util/connection"
	"istio.io/istio/pkg/test/util/policy"
	"istio.io/istio/pkg/test/util/retry"
)

const (
	rbacClusterConfigTmpl = "testdata/istio-clusterrbacconfig.yaml.tmpl"
	rbacV2RulesTmpl       = "testdata/rbacv2/istio-rbac-v2-rules.yaml.tmpl"
)

var (
	inst          istio.Instance
	isMtlsEnabled bool
)

func TestMain(m *testing.M) {
	framework.
		NewSuite("rbac_v2", m).
		// TODO(pitlv2109: Turn on the presubmit label once the test is stable.
		RequireEnvironment(environment.Kube).
		Setup(istio.SetupOnKube(&inst, setupConfig)).
		Run()
}

func setupConfig(cfg *istio.Config) {
	if cfg == nil {
		return
	}
	isMtlsEnabled = cfg.IsMtlsEnabled()
	cfg.Values["sidecarInjectorWebhook.rewriteAppHTTPProbe"] = "true"
}

func TestRBACV2(t *testing.T) {
	ctx := framework.NewContext(t)
	defer ctx.Done(t)
	ctx.RequireOrSkip(t, environment.Kube)

	env := ctx.Environment().(*kube.Environment)
	g := galley.NewOrFail(t, ctx, galley.Config{})
	p := pilot.NewOrFail(t, ctx, pilot.Config{
		Galley: g,
	})
	appInst := apps.NewOrFail(t, ctx, apps.Config{Pilot: p, Galley: g})

	appA, _ := appInst.GetAppOrFail("a", t).(apps.KubeApp)
	appB, _ := appInst.GetAppOrFail("b", t).(apps.KubeApp)
	appC, _ := appInst.GetAppOrFail("c", t).(apps.KubeApp)
	appD, _ := appInst.GetAppOrFail("d", t).(apps.KubeApp)

	cases := []testCase{
		// Port 80 is where HTTP is served, 90 is where TCP is served. When an HTTP request is at port
		// 90, this means it is a TCP request. The test framework uses HTTP to mimic TCP calls in this case.
		{request: connection.Connection{To: appA, From: appB, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/xyz"}, expectAllowed: false},
		{request: connection.Connection{To: appA, From: appB, Port: 90, Protocol: apps.AppProtocolHTTP}, expectAllowed: false},
		{request: connection.Connection{To: appA, From: appC, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/"}, expectAllowed: false},
		{request: connection.Connection{To: appA, From: appC, Port: 90, Protocol: apps.AppProtocolHTTP}, expectAllowed: false},
		{request: connection.Connection{To: appA, From: appD, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/"}, expectAllowed: false},
		{request: connection.Connection{To: appA, From: appD, Port: 90, Protocol: apps.AppProtocolHTTP}, expectAllowed: false},

		{request: connection.Connection{To: appB, From: appA, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/xyz"}, expectAllowed: isMtlsEnabled},
		{request: connection.Connection{To: appB, From: appA, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/secret"}, expectAllowed: false},
		{request: connection.Connection{To: appB, From: appA, Port: 90, Protocol: apps.AppProtocolHTTP}, expectAllowed: isMtlsEnabled},
		{request: connection.Connection{To: appB, From: appC, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/"}, expectAllowed: isMtlsEnabled},
		{request: connection.Connection{To: appB, From: appC, Port: 90, Protocol: apps.AppProtocolHTTP}, expectAllowed: isMtlsEnabled},
		{request: connection.Connection{To: appB, From: appD, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/"}, expectAllowed: isMtlsEnabled},
		{request: connection.Connection{To: appB, From: appD, Port: 90, Protocol: apps.AppProtocolHTTP}, expectAllowed: isMtlsEnabled},

		{request: connection.Connection{To: appC, From: appA, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/"}, expectAllowed: false},
		{request: connection.Connection{To: appC, From: appA, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/secrets/admin"}, expectAllowed: false},
		{request: connection.Connection{To: appC, From: appA, Port: 90, Protocol: apps.AppProtocolHTTP}, expectAllowed: false},
		{request: connection.Connection{To: appC, From: appB, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/"}, expectAllowed: false},
		{request: connection.Connection{To: appC, From: appB, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/credentials/admin"}, expectAllowed: false},
		{request: connection.Connection{To: appC, From: appB, Port: 90, Protocol: apps.AppProtocolHTTP}, expectAllowed: false},
		{request: connection.Connection{To: appC, From: appD, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/"}, expectAllowed: isMtlsEnabled},
		{request: connection.Connection{To: appC, From: appD, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/any_path/admin"}, expectAllowed: false},
		{request: connection.Connection{To: appC, From: appD, Port: 90, Protocol: apps.AppProtocolHTTP}, expectAllowed: false},

		{request: connection.Connection{To: appD, From: appA, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/xyz"}, expectAllowed: true},
		{request: connection.Connection{To: appD, From: appA, Port: 90, Protocol: apps.AppProtocolHTTP}, expectAllowed: false},
		{request: connection.Connection{To: appD, From: appB, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/"}, expectAllowed: true},
		{request: connection.Connection{To: appD, From: appB, Port: 90, Protocol: apps.AppProtocolHTTP}, expectAllowed: false},
		{request: connection.Connection{To: appD, From: appC, Port: 80, Protocol: apps.AppProtocolHTTP, Path: "/any_path"}, expectAllowed: true},
		{request: connection.Connection{To: appD, From: appC, Port: 90, Protocol: apps.AppProtocolHTTP}, expectAllowed: false},
	}

	testDir := ctx.WorkDir()
	testNameSpace := appInst.Namespace().Name()
	rbacTmplFiles := []string{rbacClusterConfigTmpl, rbacV2RulesTmpl}
	rbacYamlFiles := getRbacYamlFiles(t, testDir, testNameSpace, rbacTmplFiles)

	policy.ApplyPolicyFiles(t, env, testNameSpace, rbacYamlFiles)

	// Sleep 60 seconds for the policy to take effect.
	// TODO(pitlv2109: Check to make sure policies have been created instead.
	time.Sleep(60 * time.Second)
	for _, tc := range cases {
		retry.UntilSuccessOrFail(t, func() error {
			return checkRBACRequest(tc, connection.DenyHTTPRespCode)
		}, retry.Delay(time.Second), retry.Timeout(10*time.Second))
	}
}
