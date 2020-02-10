// Copyright 2017 Istio Authors
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
	"fmt"
	"os"
	"time"

	"istio.io/istio/pkg/spiffe"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pilot/pkg/bootstrap"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/serviceregistry"
	"istio.io/istio/pkg/cmd"
	"istio.io/istio/pkg/keepalive"
	"istio.io/pkg/collateral"
	"istio.io/pkg/ctrlz"
	"istio.io/pkg/log"
	"istio.io/pkg/version"
)

var (
	serverArgs = bootstrap.PilotArgs{
		CtrlZOptions:     ctrlz.DefaultOptions(),
		KeepaliveOptions: keepalive.DefaultOption(),
		// TODO replace with mesh config?
		InjectionOptions: bootstrap.InjectionOptions{
			InjectionDirectory: "./var/lib/istio/inject",
		},
		ValidationOptions: bootstrap.ValidationOptions{
			ValidationDirectory: "./var/lib/istio/validation",
		},

		MCPMaxMessageSize:        1024 * 1024 * 4, // default grpc maximum message size
		MCPInitialConnWindowSize: 1024 * 1024,     // default grpc InitialWindowSize
		MCPInitialWindowSize:     1024 * 1024,     // default grpc ConnWindowSize
	}

	loggingOptions = log.DefaultOptions()

	rootCmd = &cobra.Command{
		Use:          "pilot-discovery",
		Short:        "Istio Pilot.",
		Long:         "Istio Pilot provides fleet-wide traffic management capabilities in the Istio Service Mesh.",
		SilenceUsage: true,
	}

	discoveryCmd = &cobra.Command{
		Use:   "discovery",
		Short: "Start Istio proxy discovery service.",
		Args:  cobra.ExactArgs(0),
		RunE: func(c *cobra.Command, args []string) error {
			serverArgs.Config.DistributionTrackingEnabled = features.EnableDistributionTracking
			serverArgs.Config.DistributionCacheRetention = features.DistributionHistoryRetention
			cmd.PrintFlags(c.Flags())
			if err := log.Configure(loggingOptions); err != nil {
				return err
			}

			// fill in missing defaults
			serverArgs.Default()

			spiffe.SetTrustDomain(spiffe.DetermineTrustDomain(serverArgs.Config.ControllerOptions.TrustDomain, hasKubeRegistry()))

			// Create the stop channel for all of the servers.
			stop := make(chan struct{})

			// Create the server for the discovery service.
			discoveryServer, err := bootstrap.NewServer(&serverArgs)
			if err != nil {
				return fmt.Errorf("failed to create discovery service: %v", err)
			}

			// Start the server
			if err := discoveryServer.Start(stop); err != nil {
				return fmt.Errorf("failed to start discovery service: %v", err)
			}

			cmd.WaitSignal(stop)
			// Wait until we shut down. In theory this could block forever; in practice we will get
			// forcibly shut down after 30s in Kubernetes.
			discoveryServer.WaitUntilCompletion()
			return nil
		},
	}
)

// when we run on k8s, the default trust domain is 'cluster.local', otherwise it is the empty string
func hasKubeRegistry() bool {
	for _, r := range serverArgs.Service.Registries {
		if serviceregistry.ProviderID(r) == serviceregistry.Kubernetes {
			return true
		}
	}
	return false
}

func init() {
	discoveryCmd.PersistentFlags().StringSliceVar(&serverArgs.Service.Registries, "registries",
		[]string{string(serviceregistry.Kubernetes)},
		fmt.Sprintf("Comma separated list of platform service registries to read from (choose one or more from {%s, %s, %s})",
			serviceregistry.Kubernetes, serviceregistry.Consul, serviceregistry.Mock))
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.Config.ClusterRegistriesNamespace, "clusterRegistriesNamespace", metav1.NamespaceAll,
		"Namespace for ConfigMap which stores clusters configs")
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.Config.KubeConfig, "kubeconfig", "",
		"Use a Kubernetes configuration file instead of in-cluster configuration")
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.Mesh.ConfigFile, "meshConfig", "/etc/istio/config/mesh",
		fmt.Sprintf("File name for Istio mesh configuration. If not specified, a default mesh will be used."))
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.NetworksConfigFile, "networksConfig", "/etc/istio/config/meshNetworks",
		fmt.Sprintf("File name for Istio mesh networks configuration. If not specified, a default mesh networks will be used."))
	discoveryCmd.PersistentFlags().StringVarP(&serverArgs.Namespace, "namespace", "n", "",
		"Select a namespace where the controller resides. If not set, uses ${POD_NAMESPACE} environment variable")
	discoveryCmd.PersistentFlags().StringSliceVar(&serverArgs.Plugins, "plugins", bootstrap.DefaultPlugins,
		"comma separated list of networking plugins to enable")

	// MCP client flags
	discoveryCmd.PersistentFlags().IntVar(&serverArgs.MCPMaxMessageSize, "mcpMaxMsgSize", serverArgs.MCPMaxMessageSize,
		"Max message size received by MCP's grpc client")
	discoveryCmd.PersistentFlags().IntVar(&serverArgs.MCPInitialWindowSize, "mcpInitialWindowSize", serverArgs.MCPInitialWindowSize,
		"Initial window size for MCP's gRPC connection")
	discoveryCmd.PersistentFlags().IntVar(&serverArgs.MCPInitialConnWindowSize, "mcpInitialConnWindowSize", serverArgs.MCPInitialConnWindowSize,
		"Initial connection window size for MCP's gRPC connection")

	// Config Controller options
	discoveryCmd.PersistentFlags().BoolVar(&serverArgs.Config.DisableInstallCRDs, "disable-install-crds", true,
		"Disable discovery service from verifying the existence of CRDs at startup and then installing if not detected.  "+
			"It is recommended to be disable for highly available setups.")
	_ = discoveryCmd.PersistentFlags().MarkDeprecated("disable-install-crds",
		"Setting this flag has no effect. Install CRD definitions directly or with the operator")
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.Config.FileDir, "configDir", "",
		"Directory to watch for updates to config yaml files. If specified, the files will be used as the source of config, rather than a CRD client.")
	discoveryCmd.PersistentFlags().StringVarP(&serverArgs.Config.ControllerOptions.WatchedNamespace, "appNamespace",
		"a", metav1.NamespaceAll,
		"Restrict the applications namespace the controller manages; if not set, controller watches all namespaces")
	discoveryCmd.PersistentFlags().DurationVar(&serverArgs.Config.ControllerOptions.ResyncPeriod, "resync", 60*time.Second,
		"Controller resync interval")
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.Config.ControllerOptions.DomainSuffix, "domain", "cluster.local",
		"DNS domain suffix")
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.Config.ControllerOptions.TrustDomain, "trust-domain", "",
		"The domain serves to identify the system with spiffe")
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.Service.Consul.ServerURL, "consulserverURL", "",
		"URL for the Consul server")

	// using address, so it can be configured as localhost:.. (possibly UDS in future)
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.DiscoveryOptions.HTTPAddr, "httpAddr", ":8080",
		"Discovery service HTTP address")
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.DiscoveryOptions.HTTPSAddr, "httpsAddr", ":15017",
		"Injection and validation service HTTPS address")
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.DiscoveryOptions.GrpcAddr, "grpcAddr", ":15010",
		"Discovery service grpc address")
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.DiscoveryOptions.SecureGrpcAddr, "secureGrpcAddr", ":15012",
		"Discovery service grpc address, with https")
	discoveryCmd.PersistentFlags().StringVar(&serverArgs.DiscoveryOptions.MonitoringAddr, "monitoringAddr", ":15014",
		"HTTP address to use for pilot's self-monitoring information")
	discoveryCmd.PersistentFlags().BoolVar(&serverArgs.DiscoveryOptions.EnableProfiling, "profile", true,
		"Enable profiling via web interface host:port/debug/pprof")

	// Attach the Istio logging options to the command.
	loggingOptions.AttachCobraFlags(rootCmd)

	// Attach the Istio Ctrlz options to the command.
	serverArgs.CtrlZOptions.AttachCobraFlags(rootCmd)

	// Attach the Istio Keepalive options to the command.
	serverArgs.KeepaliveOptions.AttachCobraFlags(rootCmd)

	cmd.AddFlags(rootCmd)

	rootCmd.AddCommand(discoveryCmd)
	rootCmd.AddCommand(version.CobraCommand())
	rootCmd.AddCommand(collateral.CobraCommand(rootCmd, &doc.GenManHeader{
		Title:   "Istio Pilot Discovery",
		Section: "pilot-discovery CLI",
		Manual:  "Istio Pilot Discovery",
	}))

}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Errora(err)
		os.Exit(-1)
	}
}
