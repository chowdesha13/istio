/*
Copyright 2018 The Kubernetes Authors.

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

package alpha

import (
	"io"

	"github.com/spf13/cobra"
	cmdutil "k8s.io/kubernetes/cmd/kubeadm/app/cmd/util"
)

// NewCmdAlpha returns "kubeadm alpha" command.
func NewCmdAlpha(in io.Reader, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alpha",
		Short: "Kubeadm experimental sub-commands",
	}

	cmd.AddCommand(newCmdCertsUtility())
	cmd.AddCommand(newCmdKubeletUtility())
	cmd.AddCommand(newCmdKubeConfigUtility(out))
	cmd.AddCommand(newCmdPreFlightUtility())
	cmd.AddCommand(NewCmdSelfhosting(in))

	// TODO: This command should be removed as soon as the kubeadm init phase refactoring is completed.
	//		 current phases implemented as cobra.Commands should become workflow.Phases, while other utilities
	// 		 hosted under kubeadm alpha phases command should found a new home under kubeadm alpha (without phases)
	cmd.AddCommand(newCmdPhase(out))

	return cmd
}

func newCmdPhase(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "phase",
		Short: "Invoke subsets of kubeadm functions separately for a manual install",
		Long:  cmdutil.MacroCommandLongDescription,
	}

	return cmd
}
