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

package cmd

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"istio.io/istio/tools/istio-iptables/pkg/config"
	"istio.io/istio/tools/istio-iptables/pkg/constants"
	dep "istio.io/istio/tools/istio-iptables/pkg/dependencies"
	"istio.io/istio/tools/istio-iptables/pkg/validation"
	"istio.io/pkg/env"
	"istio.io/pkg/log"
)

var (
	envoyUserVar = env.RegisterStringVar(constants.EnvoyUser, "istio-proxy", "Envoy proxy username")
	// Enable interception of DNS.
	dnsCaptureByAgent = env.RegisterBoolVar("ISTIO_META_DNS_CAPTURE", false,
		"If set to true, enable the capture of outgoing DNS packets on port 53, redirecting to istio-agent on :15053").Get()
)

var rootCmd = &cobra.Command{
	Use:    "istio-iptables",
	Short:  "Set up iptables rules for Istio Sidecar",
	Long:   "istio-iptables is responsible for setting up port forwarding for Istio Sidecar.",
	PreRun: bindFlags,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := ConstructConfig(getCmdConfig())
		if err := SetupIPTables(cfg); err != nil {
			return err
		}
		return nil
	},
}

func SetupIPTables(cfg *config.Config) error {
	var ext dep.Dependencies
	if cfg.DryRun {
		ext = &dep.StdoutStubDependencies{}
	} else {
		ext = &dep.RealDependencies{
			CNIMode:          cfg.CNIMode,
			NetworkNamespace: cfg.NetworkNamespace,
		}
	}

	iptConfigurator := NewIptablesConfigurator(cfg, ext)
	if !cfg.SkipRuleApply {
		if err := iptConfigurator.run(); err != nil {
			return err
		}
	}
	if cfg.RunValidation {
		hostIP, err := getLocalIP()
		if err != nil {
			// Assume it is not handled by istio-cni and won't reuse the ValidationErrorCode
			panic(err)
		}
		validator := validation.NewValidator(cfg, hostIP)

		if err := validator.Run(); err != nil {
			handleErrorWithCode(err, constants.ValidationErrorCode)
		}
	}
	return nil
}

func GetDefaultConfig() *config.Config {
	return &config.Config{
		RestoreFormat:           true,
		ProxyPort:               "15001",
		InboundCapturePort:      "15006",
		InboundTunnelPort:       "15008",
		InboundTProxyMark:       "1337",
		InboundTProxyRouteTable: "133",
		IptablesProbePort:       constants.DefaultIptablesProbePort,
		ProbeTimeout:            constants.DefaultProbeTimeout,
		RedirectDNS:             dnsCaptureByAgent,
	}
}

func getCmdConfig() *config.Config {
	cfg := GetDefaultConfig()
	cfg.DryRun = viper.GetBool(constants.DryRun)
	cfg.RestoreFormat = viper.GetBool(constants.RestoreFormat)
	cfg.ProxyPort = viper.GetString(constants.EnvoyPort)
	cfg.InboundCapturePort = viper.GetString(constants.InboundCapturePort)
	cfg.InboundTunnelPort = viper.GetString(constants.InboundTunnelPort)
	cfg.ProxyUID = viper.GetString(constants.ProxyUID)
	cfg.ProxyGID = viper.GetString(constants.ProxyGID)
	cfg.InboundInterceptionMode = viper.GetString(constants.InboundInterceptionMode)
	cfg.InboundTProxyMark = viper.GetString(constants.InboundTProxyMark)
	cfg.InboundTProxyRouteTable = viper.GetString(constants.InboundTProxyRouteTable)
	cfg.InboundPortsInclude = viper.GetString(constants.InboundPorts)
	cfg.InboundPortsExclude = viper.GetString(constants.LocalExcludePorts)
	cfg.OutboundPortsInclude = viper.GetString(constants.OutboundPorts)
	cfg.OutboundPortsExclude = viper.GetString(constants.LocalOutboundPortsExclude)
	cfg.OutboundIPRangesInclude = viper.GetString(constants.ServiceCidr)
	cfg.OutboundIPRangesExclude = viper.GetString(constants.ServiceExcludeCidr)
	cfg.KubevirtInterfaces = viper.GetString(constants.KubeVirtInterfaces)
	cfg.IptablesProbePort = uint16(viper.GetUint(constants.IptablesProbePort))
	cfg.ProbeTimeout = viper.GetDuration(constants.ProbeTimeout)
	cfg.SkipRuleApply = viper.GetBool(constants.SkipRuleApply)
	cfg.RunValidation = viper.GetBool(constants.RunValidation)
	cfg.RedirectDNS = viper.GetBool(constants.RedirectDNS)
	cfg.CaptureAllDNS = viper.GetBool(constants.CaptureAllDNS)
	cfg.OutputPath = viper.GetString(constants.OutputPath)
	cfg.NetworkNamespace = viper.GetString(constants.NetworkNamespace)
	cfg.CNIMode = viper.GetBool(constants.CNIMode)
	return cfg
}

func ConstructConfig(cfg *config.Config) *config.Config {
	// TODO: Make this more configurable, maybe with an allowlist of users to be captured for output instead of a denylist.
	if cfg.ProxyUID == "" {
		usr, err := user.Lookup(envoyUserVar.Get())
		var userID string
		// Default to the UID of ENVOY_USER
		if err != nil {
			userID = constants.DefaultProxyUID
		} else {
			userID = usr.Uid
		}
		cfg.ProxyUID = userID
	}
	// For TPROXY as its uid and gid are same.
	if cfg.ProxyGID == "" {
		cfg.ProxyGID = cfg.ProxyUID
	}

	// Detect whether IPv6 is enabled by checking if the pod's IP address is IPv4 or IPv6.
	podIP, err := getLocalIP()
	if err != nil {
		panic(err)
	}
	cfg.EnableInboundIPv6 = podIP.To4() == nil

	// Lookup DNS nameservers. We only do this if DNS is enabled in case of some obscure theoretical
	// case where reading /etc/resolv.conf could fail.
	// If capture all DNS option is enabled, we don't need to read from the dns resolve conf. All
	// traffic to port 53 will be captured.
	if cfg.RedirectDNS && !cfg.CaptureAllDNS {
		dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			panic(fmt.Sprintf("failed to load /etc/resolv.conf: %v", err))
		}
		cfg.DNSServersV4, cfg.DNSServersV6 = SplitV4V6(dnsConfig.Servers)
	}
	return cfg
}

// getLocalIP returns the local IP address
func getLocalIP() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			return ipnet.IP, nil
		}
	}
	return nil, fmt.Errorf("no valid local IP address found")
}

func handleError(err error) {
	handleErrorWithCode(err, 1)
}

func handleErrorWithCode(err error, code int) {
	log.Error(err)
	os.Exit(code)
}

// https://github.com/spf13/viper/issues/233.
// Any viper mutation and binding should be placed in `PreRun` since they should be dynamically bound to the subcommand being executed.
func bindFlags(cmd *cobra.Command, args []string) {
	// Read in all environment variables
	viper.AutomaticEnv()
	// Replace - with _; so that environment variables are looked up correctly.
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	cfg := GetDefaultConfig()

	if err := viper.BindPFlag(constants.EnvoyPort, cmd.Flags().Lookup(constants.EnvoyPort)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.EnvoyPort, cfg.ProxyPort)

	if err := viper.BindPFlag(constants.InboundCapturePort, cmd.Flags().Lookup(constants.InboundCapturePort)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.InboundCapturePort, cfg.InboundCapturePort)

	if err := viper.BindPFlag(constants.InboundTunnelPort, cmd.Flags().Lookup(constants.InboundTunnelPort)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.InboundTunnelPort, cfg.InboundTunnelPort)

	if err := viper.BindPFlag(constants.ProxyUID, cmd.Flags().Lookup(constants.ProxyUID)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.ProxyUID, cfg.ProxyUID)

	if err := viper.BindPFlag(constants.ProxyGID, cmd.Flags().Lookup(constants.ProxyGID)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.ProxyGID, cfg.ProxyGID)

	if err := viper.BindPFlag(constants.InboundInterceptionMode, cmd.Flags().Lookup(constants.InboundInterceptionMode)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.InboundInterceptionMode, cfg.InboundInterceptionMode)

	if err := viper.BindPFlag(constants.InboundPorts, cmd.Flags().Lookup(constants.InboundPorts)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.InboundPorts, cfg.InboundPortsInclude)

	if err := viper.BindPFlag(constants.LocalExcludePorts, cmd.Flags().Lookup(constants.LocalExcludePorts)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.LocalExcludePorts, cfg.InboundPortsExclude)

	if err := viper.BindPFlag(constants.ServiceCidr, cmd.Flags().Lookup(constants.ServiceCidr)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.ServiceCidr, cfg.OutboundIPRangesInclude)

	if err := viper.BindPFlag(constants.ServiceExcludeCidr, cmd.Flags().Lookup(constants.ServiceExcludeCidr)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.ServiceExcludeCidr, cfg.OutboundIPRangesExclude)

	if err := viper.BindPFlag(constants.OutboundPorts, cmd.Flags().Lookup(constants.OutboundPorts)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.OutboundPorts, cfg.OutboundPortsInclude)

	if err := viper.BindPFlag(constants.LocalOutboundPortsExclude, cmd.Flags().Lookup(constants.LocalOutboundPortsExclude)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.LocalOutboundPortsExclude, cfg.OutboundPortsExclude)

	if err := viper.BindPFlag(constants.KubeVirtInterfaces, cmd.Flags().Lookup(constants.KubeVirtInterfaces)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.KubeVirtInterfaces, cfg.KubevirtInterfaces)

	if err := viper.BindPFlag(constants.InboundTProxyMark, cmd.Flags().Lookup(constants.InboundTProxyMark)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.InboundTProxyMark, cfg.InboundTProxyMark)

	if err := viper.BindPFlag(constants.InboundTProxyRouteTable, cmd.Flags().Lookup(constants.InboundTProxyRouteTable)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.InboundTProxyRouteTable, cfg.InboundTProxyRouteTable)

	if err := viper.BindPFlag(constants.DryRun, cmd.Flags().Lookup(constants.DryRun)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.DryRun, cfg.DryRun)

	if err := viper.BindPFlag(constants.RestoreFormat, cmd.Flags().Lookup(constants.RestoreFormat)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.RestoreFormat, true)

	if err := viper.BindPFlag(constants.IptablesProbePort, cmd.Flags().Lookup(constants.IptablesProbePort)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.IptablesProbePort, cfg.IptablesProbePort)

	if err := viper.BindPFlag(constants.ProbeTimeout, cmd.Flags().Lookup(constants.ProbeTimeout)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.ProbeTimeout, cfg.ProbeTimeout)

	if err := viper.BindPFlag(constants.SkipRuleApply, cmd.Flags().Lookup(constants.SkipRuleApply)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.SkipRuleApply, cfg.SkipRuleApply)

	if err := viper.BindPFlag(constants.RunValidation, cmd.Flags().Lookup(constants.RunValidation)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.RunValidation, cfg.RunValidation)

	if err := viper.BindPFlag(constants.RedirectDNS, cmd.Flags().Lookup(constants.RedirectDNS)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.RedirectDNS, cfg.RedirectDNS)

	if err := viper.BindPFlag(constants.CaptureAllDNS, cmd.Flags().Lookup(constants.CaptureAllDNS)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.CaptureAllDNS, cfg.CaptureAllDNS)

	if err := viper.BindPFlag(constants.OutputPath, cmd.Flags().Lookup(constants.OutputPath)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.OutputPath, cfg.OutputPath)

	if err := viper.BindPFlag(constants.NetworkNamespace, cmd.Flags().Lookup(constants.NetworkNamespace)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.NetworkNamespace, cfg.NetworkNamespace)

	if err := viper.BindPFlag(constants.CNIMode, cmd.Flags().Lookup(constants.CNIMode)); err != nil {
		handleError(err)
	}
	viper.SetDefault(constants.CNIMode, cfg.CNIMode)
}

// https://github.com/spf13/viper/issues/233.
// Only adding flags in `init()` while moving its binding to Viper and value defaulting as part of the command execution.
// Otherwise, the flag with the same name shared across subcommands will be overwritten by the last.
func init() {
	defaultCfg := GetDefaultConfig()

	rootCmd.Flags().StringP(constants.EnvoyPort, "p", defaultCfg.ProxyPort,
		"Specify the envoy port to which redirect all TCP traffic (default $ENVOY_PORT = 15001)")

	rootCmd.Flags().StringP(constants.InboundCapturePort, "z", defaultCfg.InboundCapturePort,
		"Port to which all inbound TCP traffic to the pod/VM should be redirected to (default $INBOUND_CAPTURE_PORT = 15006)")

	rootCmd.Flags().StringP(constants.InboundTunnelPort, "e", defaultCfg.InboundTunnelPort,
		"Specify the istio tunnel port for inbound tcp traffic (default $INBOUND_TUNNEL_PORT = 15008)")

	rootCmd.Flags().StringP(constants.ProxyUID, "u", defaultCfg.ProxyUID,
		"Specify the UID of the user for which the redirection is not applied. Typically, this is the UID of the proxy container")

	rootCmd.Flags().StringP(constants.ProxyGID, "g", defaultCfg.ProxyGID,
		"Specify the GID of the user for which the redirection is not applied. (same default value as -u param)")

	rootCmd.Flags().StringP(constants.InboundInterceptionMode, "m", defaultCfg.InboundInterceptionMode,
		"The mode used to redirect inbound connections to Envoy, either \"REDIRECT\" or \"TPROXY\"")

	rootCmd.Flags().StringP(constants.InboundPorts, "b", defaultCfg.InboundPortsInclude,
		"Comma separated list of inbound ports for which traffic is to be redirected to Envoy (optional). "+
			"The wildcard character \"*\" can be used to configure redirection for all ports. An empty list will disable")

	rootCmd.Flags().StringP(constants.LocalExcludePorts, "d", defaultCfg.InboundPortsExclude,
		"Comma separated list of inbound ports to be excluded from redirection to Envoy (optional). "+
			"Only applies  when all inbound traffic (i.e. \"*\") is being redirected (default to $ISTIO_LOCAL_EXCLUDE_PORTS)")

	rootCmd.Flags().StringP(constants.ServiceCidr, "i", defaultCfg.OutboundIPRangesInclude,
		"Comma separated list of IP ranges in CIDR form to redirect to envoy (optional). "+
			"The wildcard character \"*\" can be used to redirect all outbound traffic. An empty list will disable all outbound")

	rootCmd.Flags().StringP(constants.ServiceExcludeCidr, "x", defaultCfg.OutboundIPRangesExclude,
		"Comma separated list of IP ranges in CIDR form to be excluded from redirection. "+
			"Only applies when all  outbound traffic (i.e. \"*\") is being redirected (default to $ISTIO_SERVICE_EXCLUDE_CIDR)")

	rootCmd.Flags().StringP(constants.OutboundPorts, "q", defaultCfg.OutboundPortsInclude,
		"Comma separated list of outbound ports to be explicitly included for redirection to Envoy")

	rootCmd.Flags().StringP(constants.LocalOutboundPortsExclude, "o", defaultCfg.OutboundPortsExclude,
		"Comma separated list of outbound ports to be excluded from redirection to Envoy")

	rootCmd.Flags().StringP(constants.KubeVirtInterfaces, "k", defaultCfg.KubevirtInterfaces,
		"Comma separated list of virtual interfaces whose inbound traffic (from VM) will be treated as outbound")

	rootCmd.Flags().StringP(constants.InboundTProxyMark, "t", defaultCfg.InboundTProxyMark, "")

	rootCmd.Flags().StringP(constants.InboundTProxyRouteTable, "r", defaultCfg.InboundTProxyRouteTable, "")

	rootCmd.Flags().BoolP(constants.DryRun, "n", defaultCfg.DryRun, "Do not call any external dependencies like iptables")

	rootCmd.Flags().BoolP(constants.RestoreFormat, "f", defaultCfg.RestoreFormat, "Print iptables rules in iptables-restore interpretable format")

	rootCmd.Flags().String(constants.IptablesProbePort, strconv.Itoa(int(defaultCfg.IptablesProbePort)),
		"set listen port for failure detection")

	rootCmd.Flags().Duration(constants.ProbeTimeout, defaultCfg.ProbeTimeout, "failure detection timeout")

	rootCmd.Flags().Bool(constants.SkipRuleApply, defaultCfg.SkipRuleApply, "Skip iptables apply")

	rootCmd.Flags().Bool(constants.RunValidation, defaultCfg.RunValidation, "Validate iptables")

	rootCmd.Flags().Bool(constants.RedirectDNS, defaultCfg.RedirectDNS, "Enable capture of dns traffic by istio-agent")

	rootCmd.Flags().Bool(constants.CaptureAllDNS, defaultCfg.CaptureAllDNS,
		"Instead of only capturing DNS traffic to DNS server IP, capture all DNS traffic at port 53. This setting is only effective when redirect dns is enabled.")

	rootCmd.Flags().String(constants.OutputPath, defaultCfg.OutputPath, "A file path to write the applied iptables rules to.")

	rootCmd.Flags().String(constants.NetworkNamespace, defaultCfg.NetworkNamespace, "The network namespace that iptables rules should be applied to.")

	rootCmd.Flags().Bool(constants.CNIMode, defaultCfg.CNIMode, "Whether to run as CNI plugin.")
}

func GetCommand() *cobra.Command {
	return rootCmd
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		handleError(err)
	}
}
