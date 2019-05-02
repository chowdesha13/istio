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

/*
Package workflow implements a workflow manager to be used for
implementing composable kubeadm workflows.

Composable kubeadm workflows are built by an ordered sequence of phases;
each phase can have it's own, nested, ordered sequence of sub phases.
For instance

	preflight     	Run master pre-flight checks
	certs         	Generates all PKI assets necessary to establish the control plane
		/ca             Generates a self-signed Kubernetes CA to provision identities for Kubernetes components
		/apiserver      Generates an API server serving certificate and key
		...
	kubeconfig		Generates all kubeconfig files necessary to establish the control plane
		/admin          Generates a kubeconfig file for the admin to use and for kubeadm itself
		/kubelet        Generates a kubeconfig file for the kubelet to use.
		...
	...

Phases are designed to be reusable across different kubeadm workflows thus allowing
e.g. reuse of phase certs in both kubeadm init and kubeadm join --control-plane workflows.

Each workflow can be defined and managed using a Runner, that will run all
the phases according to the given order; nested phases will be executed immediately
after their parent phase.

The phase runner can be bound to a cobra command; this operation sets the command description
giving evidence of the list of phases, and automatically creates sub commands
for invoking phases atomically.

Autogenerated sub commands get flags according to the following rule:

- global flags will be always inherited by autogenerated commands (this is managed by cobra)

- local flags defined in the parent command might be inherited by autogenerated commands,
but this requires explicit opt-in so each phase can select the subset of relevant flags

- it is possible to define additional flags that might be inherited by autogenerated commands
via explicit opt-in, but are not applied to the parent command

In order to keep flags definition under control, please refer to the
"k8s.io/kubernetes/cmd/kubeadm/app/cmd/options" package.
*/
package workflow
