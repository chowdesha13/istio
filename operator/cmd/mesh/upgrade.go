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

package mesh

import (
	"github.com/spf13/cobra"

	"istio.io/istio/operator/pkg/util/clog"
	"istio.io/pkg/log"
)

type upgradeArgs struct {
	*InstallArgs
}

// UpgradeCmd upgrades Istio control plane in-place with eligibility checks.
func UpgradeCmd(logOpts *log.Options) *cobra.Command {
	rootArgs := &RootArgs{}
	upgradeArgs := &upgradeArgs{
		InstallArgs: &InstallArgs{},
	}
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade Istio control plane in-place",
		Long: "The upgrade command is an alias for the install command" +
			" that performs additional upgrade-related checks using `--show-diff` flag",
		RunE: func(cmd *cobra.Command, args []string) (e error) {
			l := clog.NewConsoleLogger(cmd.OutOrStdout(), cmd.ErrOrStderr(), installerScope)
			p := NewPrinterForWriter(cmd.OutOrStderr())
			upgradeArgs.InstallArgs.ShowDiff = true
			return Install(rootArgs, upgradeArgs.InstallArgs, logOpts, cmd.OutOrStdout(), l, p)
		},
	}
	addFlags(cmd, rootArgs)
	addInstallFlags(cmd, upgradeArgs.InstallArgs)
	return cmd
}
