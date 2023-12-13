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

package nodeagent

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/cni/pkg/iptables"
	istiolog "istio.io/istio/pkg/log"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/tools/istio-iptables/pkg/dependencies"
)

func setupLogging() {
	opts := istiolog.DefaultOptions()
	opts.SetOutputLevel(istiolog.OverrideScopeName, istiolog.DebugLevel)
	istiolog.Configure(opts)
	for _, scope := range istiolog.Scopes() {
		scope.SetOutputLevel(istiolog.DebugLevel)
	}
}

type netTestFixture struct {
	netServer            *NetServer
	podNsMap             *podNetnsCache
	ztunnelServer        *fakeZtunnel
	iptablesConfigurator *iptables.IptablesConfigurator
	nlDeps               *fakeIptablesDeps
}

func getTestFixure(ctx context.Context) netTestFixture {
	podNsMap := newPodNetnsCache(openNsTestOverride)
	nlDeps := &fakeIptablesDeps{}
	iptablesConfigurator := iptables.NewIptablesConfigurator(nil, &dependencies.StdoutStubDependencies{}, nlDeps)

	ztunnelServer := &fakeZtunnel{}

	netServer := newNetServer(ztunnelServer, podNsMap, iptablesConfigurator, NewPodNetnsProcFinder(fakeFs()))

	netServer.netnsRunner = func(fdable NetnsFd, toRun func() error) error {
		return toRun()
	}
	netServer.Start(ctx)
	return netTestFixture{
		netServer:            netServer,
		podNsMap:             podNsMap,
		ztunnelServer:        ztunnelServer,
		iptablesConfigurator: iptablesConfigurator,
		nlDeps:               nlDeps,
	}
}

func TestServerAddPod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setupLogging()
	fixture := getTestFixure(ctx)
	netServer := fixture.netServer
	ztunnelServer := fixture.ztunnelServer
	podMeta := metav1.ObjectMeta{
		Name:      "foo",
		Namespace: "bar",
		UID:       "123",
	}
	podIP := netip.MustParseAddr("99.9.9.9")
	podIPs := []netip.Addr{podIP}
	err := netServer.AddPodToMesh(ctx, &corev1.Pod{ObjectMeta: podMeta}, podIPs, "fakenetns")
	assert.NoError(t, err)
	assert.Equal(t, 1, ztunnelServer.addedPods.Load())
}

func TestServerRemovePod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setupLogging()
	fixture := getTestFixure(ctx)
	netServer := fixture.netServer
	ztunnelServer := fixture.ztunnelServer
	nlDeps := fixture.nlDeps
	podMeta := metav1.ObjectMeta{
		Name:      "foo",
		Namespace: "bar",
		UID:       "123",
	}

	// this is usually called after add. so manually add the pod uid for now
	fakens := newFakeNs(123)
	closed := fakens.closed
	fixture.podNsMap.UpsertPodCacheWithNetns(string(podMeta.UID), fakens)
	err := netServer.RemovePodFromMesh(ctx, &corev1.Pod{ObjectMeta: podMeta})
	assert.NoError(t, err)
	assert.Equal(t, ztunnelServer.deletedPods.Load(), 1)
	assert.Equal(t, nlDeps.DelInpodMarkIPRuleCnt.Load(), 1)
	assert.Equal(t, nlDeps.DelLoopbackRoutesCnt.Load(), 1)
	// make sure the uid was taken from cache and netns closed
	netns := fixture.podNsMap.Take(string(podMeta.UID))
	assert.Equal(t, nil, netns)

	// run gc to clean up ns:

	//revive:disable-next-line:call-to-gc Just a test that we are cleaning up the netns
	runtime.GC()
	assertNSClosed(t, closed)
}

func TestServerDeletePod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setupLogging()
	fixture := getTestFixure(ctx)
	netServer := fixture.netServer
	ztunnelServer := fixture.ztunnelServer
	nlDeps := fixture.nlDeps
	podMeta := metav1.ObjectMeta{
		Name:      "foo",
		Namespace: "bar",
		UID:       "123",
	}

	// this is usually called after add. so manually add the pod uid for now
	fakens := newFakeNs(123)
	closed := fakens.closed
	fixture.podNsMap.UpsertPodCacheWithNetns(string(podMeta.UID), fakens)
	err := netServer.DelPodFromMesh(ctx, &corev1.Pod{ObjectMeta: podMeta})
	assert.NoError(t, err)
	assert.Equal(t, ztunnelServer.deletedPods.Load(), 1)
	// with delete iptables is not called, as there is no need to delete the iptables rules
	// from a pod that's gone from the cluster.
	assert.Equal(t, nlDeps.DelInpodMarkIPRuleCnt.Load(), 0)
	assert.Equal(t, nlDeps.DelLoopbackRoutesCnt.Load(), 0)
	// make sure the uid was taken from cache and netns closed
	netns := fixture.podNsMap.Take(string(podMeta.UID))
	assert.Equal(t, nil, netns)
	// run gc to clean up ns:

	//revive:disable-next-line:call-to-gc Just a test that we are cleaning up the netns
	runtime.GC()
	assertNSClosed(t, closed)
}

func TestServerAddPodWithNoNetns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setupLogging()
	fixture := getTestFixure(ctx)
	netServer := fixture.netServer
	ztunnelServer := fixture.ztunnelServer
	podMeta := metav1.ObjectMeta{
		Name:      "foo",
		Namespace: "bar",
		// this uid exists in the fake filesystem.
		UID: "863b91d4-4b68-4efa-917f-4b560e3e86aa",
	}
	podIP := netip.MustParseAddr("99.9.9.9")
	podIPs := []netip.Addr{podIP}
	err := netServer.AddPodToMesh(ctx, &corev1.Pod{ObjectMeta: podMeta}, podIPs, "")
	assert.NoError(t, err)
	assert.Equal(t, ztunnelServer.addedPods.Load(), 1)
}

func TestReturnsPartialErrorOnZtunnelFail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setupLogging()
	fixture := getTestFixure(ctx)
	netServer := fixture.netServer
	ztunnelServer := fixture.ztunnelServer

	podMeta := metav1.ObjectMeta{
		Name:      "foo",
		Namespace: "bar",
		UID:       "123",
	}
	ztunnelServer.addError = errors.New("fake error")
	podIP := netip.MustParseAddr("99.9.9.9")
	podIPs := []netip.Addr{podIP}
	err := netServer.AddPodToMesh(ctx, &corev1.Pod{ObjectMeta: podMeta}, podIPs, "faksens")
	assert.Equal(t, ztunnelServer.addedPods.Load(), 1)
	if !errors.Is(err, ErrPartialAdd) {
		t.Fatal("expected partial error")
	}
}

func TestDoesntReturnsPartialErrorOnIptablesFail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setupLogging()
	fixture := getTestFixure(ctx)
	netServer := fixture.netServer
	ztunnelServer := fixture.ztunnelServer
	nlDeps := fixture.nlDeps
	nlDeps.AddRouteErr = errors.New("fake error")

	podMeta := metav1.ObjectMeta{
		Name:      "foo",
		Namespace: "bar",
		UID:       "123",
	}
	podIP := netip.MustParseAddr("99.9.9.9")
	podIPs := []netip.Addr{podIP}
	err := netServer.AddPodToMesh(ctx, &corev1.Pod{ObjectMeta: podMeta}, podIPs, "faksens")
	// no calls to ztunnel if iptables failed
	assert.Equal(t, ztunnelServer.addedPods.Load(), 0)

	// error is not partial error
	if errors.Is(err, ErrPartialAdd) {
		t.Fatal("expected not a partial error")
	}
}

func TestConstructInitialSnap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setupLogging()
	fixture := getTestFixure(ctx)
	netServer := fixture.netServer

	podMeta := metav1.ObjectMeta{
		Name:      "foo",
		Namespace: "bar",
		UID:       types.UID("863b91d4-4b68-4efa-917f-4b560e3e86aa"),
	}
	pod := &corev1.Pod{ObjectMeta: podMeta}

	err := netServer.ConstructInitialSnapshot([]*corev1.Pod{pod})
	assert.NoError(t, err)
	if fixture.podNsMap.Get("863b91d4-4b68-4efa-917f-4b560e3e86aa") == nil {
		t.Fatal("expected pod to be in cache")
	}
}

// for tests that call `runtime.GC()` - we have no control over when the GC is actually scheduled,
// and it is flake-prone to check for closure after calling it, this retries for a bit to make
// sure the netns is closed eventually.
func assertNSClosed(t *testing.T, closed *atomic.Bool) {
	for i := 0; i < 5; i++ {
		if closed.Load() {
			return
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatal("NS not closed")
}
