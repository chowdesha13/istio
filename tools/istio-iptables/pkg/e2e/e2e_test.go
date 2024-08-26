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

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	// Create a new mount namespace.
	"github.com/howardjohn/unshare-go/mountns"
	// Create a new network namespace. This will have the 'lo' interface ready but nothing else.
	_ "github.com/howardjohn/unshare-go/netns"
	"github.com/howardjohn/unshare-go/userns"

	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/test/util/assert"
	cleancmd "istio.io/istio/tools/istio-clean-iptables/pkg/cmd"
	iptablescmd "istio.io/istio/tools/istio-iptables/pkg/cmd"
)

func TestIptablesCleanRoundTrip(t *testing.T) {
	setup(t)
	// We only have UID 0 in our namespace, so always set it to that
	const proxyUID = "--proxy-uid=0"
	t.Run("basic", func(t *testing.T) {
		assert.NoError(t, runIptables(proxyUID))
		assert.NoError(t, runIptablesClean(proxyUID))
		validateIptablesClean(t)
	})
	t.Run("dns", func(t *testing.T) {
		t.Skip("https://github.com/istio/istio/issues/52835")
		assert.NoError(t, runIptables(proxyUID, "--redirect-dns"))
		assert.NoError(t, runIptablesClean(proxyUID, "--redirect-dns"))
		validateIptablesClean(t)
	})
}

func validateIptablesClean(t *testing.T) {
	cur := iptablesSave(t)
	if strings.Contains(cur, "ISTIO") {
		t.Fatalf("Istio rules leftover: %v", cur)
	}
}

var initialized = &sync.Once{}

func setup(t *testing.T) {
	initialized.Do(func() {
		// Setup group namespace so iptables --gid-owner will work
		assert.NoError(t, userns.WriteGroupMap(map[uint32]uint32{userns.OriginalGID(): 0}))
		// Istio iptables expects to find a non-localhost IP in some interface
		assert.NoError(t, exec.Command("ip", "addr", "add", "240.240.240.240/32", "dev", "lo").Run())
		// Put a new file we have permission to access over xtables.lock
		xtables := filepath.Join(t.TempDir(), "xtables.lock")
		_, err := os.Create(xtables)
		assert.NoError(t, err)
		_ = os.Mkdir("/run", 0o777)
		_ = mountns.BindMount(xtables, "/run/xtables.lock")
	})
}

func runIptables(args ...string) error {
	c := iptablescmd.GetCommand(log.DefaultOptions())
	c.SetArgs(args)
	return c.Execute()
}

func runIptablesClean(args ...string) error {
	c := cleancmd.GetCommand(log.DefaultOptions())
	c.SetArgs(args)
	return c.Execute()
}

func iptablesSave(t *testing.T) string {
	res, err := exec.Command("iptables-save").CombinedOutput()
	assert.NoError(t, err)
	return string(res)
}
