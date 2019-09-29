// Copyright 2018 Istio Authors
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
	"io"
	"regexp"
	"strings"

	"github.com/ghodss/yaml"
	"istio.io/pkg/log"

	"github.com/spf13/cobra"

	"istio.io/istio/istioctl/pkg/util/handlers"
	"istio.io/istio/istioctl/pkg/writer/envoy/clusters"
	"istio.io/istio/istioctl/pkg/writer/envoy/configdump"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/host"
)

const (
	jsonOutput    = "json"
	summaryOutput = "short"
)

var (
	fqdn, direction, subset string
	port                    int

	address, listenerType string

	routeName string

	clusterName, status string
)

// Level is an enumeration of all supported log levels.
type Level int

const (
	defaultLoggerName  = "level"
	defaultOutputLevel = WarningLevel
)

const (
	// OffLevel disables logging
	OffLevel Level = iota
	// CriticalLevel enables critical level logging
	CriticalLevel
	// ErrorLevel enables error level logging
	ErrorLevel
	// WarningLevel enables warning level logging
	WarningLevel
	// InfoLevel enables info level logging
	InfoLevel
	// DebugLevel enables debug level logging
	DebugLevel
	// TraceLevel enables trace level logging
	TraceLevel
)

// existing sorted active loggers
var activeLoggers = []string{
	"admin",
	"all",
	"aws",
	"assert",
	"backtrace",
	"client",
	"config",
	"connection",
	"dubbo",
	"file",
	"filter",
	"forward_proxy",
	"grpc",
	"hc",
	"health_checker",
	"http",
	"http2",
	"hystrix",
	"init",
	"io",
	"jwt",
	"kafka",
	"lua",
	"main",
	"misc",
	"mongo",
	"quic",
	"pool",
	"rbac",
	"redis",
	"router",
	"runtime",
	"stats",
	"secret",
	"tap",
	"testing",
	"thrift",
	"tracing",
	"upstream",
	"udp",
	"wasm",
}

var levelToString = map[Level]string{
	TraceLevel:    "trace",
	DebugLevel:    "debug",
	InfoLevel:     "info",
	WarningLevel:  "warning",
	ErrorLevel:    "error",
	CriticalLevel: "critical",
	OffLevel:      "off",
}

var stringToLevel = map[string]Level{
	"trace":    TraceLevel,
	"debug":    DebugLevel,
	"info":     InfoLevel,
	"warning":  WarningLevel,
	"error":    ErrorLevel,
	"critical": CriticalLevel,
	"off":      OffLevel,
}

var (
	loggerLevelString = ""
	reset             = false
)

func setupConfigdumpEnvoyConfigWriter(podName, podNamespace string, out io.Writer) (*configdump.ConfigWriter, error) {
	kubeClient, err := clientExecFactory(kubeconfig, configContext)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %v", err)
	}
	path := "config_dump"
	debug, err := kubeClient.EnvoyDo(podName, podNamespace, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command on envoy: %v", err)
	}
	cw := &configdump.ConfigWriter{Stdout: out}
	err = cw.Prime(debug)
	if err != nil {
		return nil, err
	}
	return cw, nil
}

func setupEnvoyLogConfig(param, podName, podNamespace string) (string, error) {
	kubeClient, err := clientExecFactory(kubeconfig, configContext)
	if err != nil {
		return "", fmt.Errorf("failed to create k8s client: %v", err)
	}
	path := "logging"
	if param != "" {
		path = path + "?" + param
	}
	result, err := kubeClient.EnvoyDo(podName, podNamespace, "POST", path, nil)
	if err != nil {
		return "", fmt.Errorf("failed to execute command on envoy: %v", err)
	}
	return string(result), nil
}

func getLogLevelFromConfigMap() (string, error) {
	valuesConfig, err := getValuesFromConfigMap(kubeconfig)
	if err != nil {
		return "", err
	}
	var values struct {
		SidecarInjectorWebhook struct {
			Global struct {
				Proxy struct {
					LogLevel string `json:"logLevel"`
				} `json:"proxy"`
			} `json:"global"`
		} `json:"sidecarInjectorWebhook"`
	}
	if err := yaml.Unmarshal([]byte(valuesConfig), &values); err != nil {
		return "", fmt.Errorf("failed to parse values config: %v [%v]", err, valuesConfig)
	}
	return values.SidecarInjectorWebhook.Global.Proxy.LogLevel, nil
}

// TODO(fisherxu): migrate this to config dump when implemented in Envoy
// Issue to track -> https://github.com/envoyproxy/envoy/issues/3362
func setupClustersEnvoyConfigWriter(podName, podNamespace string, out io.Writer) (*clusters.ConfigWriter, error) {
	kubeClient, err := clientExecFactory(kubeconfig, configContext)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %v", err)
	}
	path := "clusters?format=json"
	debug, err := kubeClient.EnvoyDo(podName, podNamespace, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command on envoy: %v", err)
	}
	cw := &clusters.ConfigWriter{Stdout: out}
	err = cw.Prime(debug)
	if err != nil {
		return nil, err
	}
	return cw, nil
}

func proxyConfig() *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "proxy-config",
		Short: "Retrieve information about proxy configuration from Envoy [kube only]",
		Long:  `A group of commands used to retrieve information about proxy configuration from the Envoy config dump`,
		Example: `  # Retrieve information about proxy configuration from an Envoy instance.
  istioctl proxy-config <clusters|listeners|routes|endpoints|bootstrap> <pod-name[.namespace]>`,
		Aliases: []string{"pc"},
	}

	configCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", summaryOutput, "Output format: one of json|short")

	clusterConfigCmd := &cobra.Command{
		Use:   "cluster <pod-name[.namespace]>",
		Short: "Retrieves cluster configuration for the Envoy in the specified pod",
		Long:  `Retrieve information about cluster configuration for the Envoy instance in the specified pod.`,
		Example: `  # Retrieve summary about cluster configuration for a given pod from Envoy.
  istioctl proxy-config clusters <pod-name[.namespace]>

  # Retrieve cluster summary for clusters with port 9080.
  istioctl proxy-config clusters <pod-name[.namespace]> --port 9080

  # Retrieve full cluster dump for clusters that are inbound with a FQDN of details.default.svc.cluster.local.
  istioctl proxy-config clusters <pod-name[.namespace]> --fqdn details.default.svc.cluster.local --direction inbound -o json
`,
		Aliases: []string{"clusters", "c"},
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				cmd.Println(cmd.UsageString())
				return fmt.Errorf("cluster requires pod name")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			podName, ns := handlers.InferPodInfo(args[0], handlers.HandleNamespace(namespace, defaultNamespace))
			configWriter, err := setupConfigdumpEnvoyConfigWriter(podName, ns, c.OutOrStdout())
			if err != nil {
				return err
			}
			filter := configdump.ClusterFilter{
				FQDN:      host.Name(fqdn),
				Port:      port,
				Subset:    subset,
				Direction: model.TrafficDirection(direction),
			}
			switch outputFormat {
			case summaryOutput:
				return configWriter.PrintClusterSummary(filter)
			case jsonOutput:
				return configWriter.PrintClusterDump(filter)
			default:
				return fmt.Errorf("output format %q not supported", outputFormat)
			}
		},
	}

	clusterConfigCmd.PersistentFlags().StringVar(&fqdn, "fqdn", "", "Filter clusters by substring of Service FQDN field")
	clusterConfigCmd.PersistentFlags().StringVar(&direction, "direction", "", "Filter clusters by Direction field")
	clusterConfigCmd.PersistentFlags().StringVar(&subset, "subset", "", "Filter clusters by substring of Subset field")
	clusterConfigCmd.PersistentFlags().IntVar(&port, "port", 0, "Filter clusters by Port field")

	listenerConfigCmd := &cobra.Command{
		Use:   "listener <pod-name[.namespace]>",
		Short: "Retrieves listener configuration for the Envoy in the specified pod",
		Long:  `Retrieve information about listener configuration for the Envoy instance in the specified pod.`,
		Example: `  # Retrieve summary about listener configuration for a given pod from Envoy.
  istioctl proxy-config listeners <pod-name[.namespace]>

  # Retrieve listener summary for listeners with port 9080.
  istioctl proxy-config listeners <pod-name[.namespace]> --port 9080

  # Retrieve full listener dump for HTTP listeners with a wildcard address (0.0.0.0).
  istioctl proxy-config listeners <pod-name[.namespace]> --type HTTP --address 0.0.0.0 -o json
`,
		Aliases: []string{"listeners", "l"},
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				cmd.Println(cmd.UsageString())
				return fmt.Errorf("listener requires pod name")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			podName, ns := handlers.InferPodInfo(args[0], handlers.HandleNamespace(namespace, defaultNamespace))
			configWriter, err := setupConfigdumpEnvoyConfigWriter(podName, ns, c.OutOrStdout())
			if err != nil {
				return err
			}
			filter := configdump.ListenerFilter{
				Address: address,
				Port:    uint32(port),
				Type:    listenerType,
			}

			switch outputFormat {
			case summaryOutput:
				return configWriter.PrintListenerSummary(filter)
			case jsonOutput:
				return configWriter.PrintListenerDump(filter)
			default:
				return fmt.Errorf("output format %q not supported", outputFormat)
			}
		},
	}

	listenerConfigCmd.PersistentFlags().StringVar(&address, "address", "", "Filter listeners by address field")
	listenerConfigCmd.PersistentFlags().StringVar(&listenerType, "type", "", "Filter listeners by type field")
	listenerConfigCmd.PersistentFlags().IntVar(&port, "port", 0, "Filter listeners by Port field")

	logCmd := &cobra.Command{
		Use:   "log <pod-name[.namespace]>",
		Short: "(experimental) Retrieves logging levels of the Envoy in the specified pod",
		Long:  "(experimental) Retrieve information about logging levels of the Envoy instance in the specified pod, and update optionally",
		Example: `  # Retrieve information about logging levels for a given pod from Envoy.
  istioctl proxy-config log <pod-name[.namespace]>

  # Update levels of the specified loggers and retrieve all the information about logging levels.
  istioctl proxy-config log <pod-name[.namespace]> --level all:warning,http:debug,redis:debug

  # Reset levels of all the loggers to default value (warning) and retrieve all the information about logging levels.
  istioctl proxy-config log <pod-name[.namespace]> -r
`,
		Aliases: []string{"o"},
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				cmd.Println(cmd.UsageString())
				return fmt.Errorf("log requires pod name")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			podName, ns := handlers.InferPodInfo(args[0], handlers.HandleNamespace(namespace, defaultNamespace))
			loggerNames, err := setupEnvoyLogConfig("", podName, ns)
			if err != nil {
				return err
			}

			destLoggerLevels := map[string]Level{}
			if reset {
				// reset logging level to `defaultOutputLevel`, and ignore the `level` option
				levelString, _ := getLogLevelFromConfigMap()
				level, ok := stringToLevel[levelString]
				if ok {
					destLoggerLevels[defaultLoggerName] = level
				} else {
					log.Warnf("unable to get logLevel from ConfigMap istio-sidecar-injector, using default value: %v",
						levelToString[defaultOutputLevel])
					destLoggerLevels[defaultLoggerName] = defaultOutputLevel
				}
			} else if loggerLevelString != "" {
				levels := strings.Split(loggerLevelString, ",")
				for _, ol := range levels {
					if !strings.Contains(ol, ":") && !strings.Contains(ol, "=") {
						level, ok := stringToLevel[ol]
						if ok {
							destLoggerLevels = map[string]Level{
								defaultLoggerName: level,
							}
						} else {
							return fmt.Errorf("unrecognized logging level: %v", ol)
						}
					} else {
						loggerLevel := regexp.MustCompile(`[:=]`).Split(ol, 2)
						if !strings.Contains(loggerNames, loggerLevel[0]) {
							return fmt.Errorf("unrecognized logger name: %v", loggerLevel[0])
						}
						level, ok := stringToLevel[loggerLevel[1]]
						if !ok {
							return fmt.Errorf("unrecognized logging level: %v", loggerLevel[1])
						}
						destLoggerLevels[loggerLevel[0]] = level
					}
				}
			}

			var resp string
			if len(destLoggerLevels) == 0 {
				resp, err = setupEnvoyLogConfig("", podName, ns)
			} else {
				if ll, ok := destLoggerLevels[defaultLoggerName]; ok {
					// update levels of all loggers first
					resp, err = setupEnvoyLogConfig(defaultLoggerName+"="+levelToString[ll], podName, ns)
					delete(destLoggerLevels, defaultLoggerName)
				}
				for lg, ll := range destLoggerLevels {
					resp, err = setupEnvoyLogConfig(lg+"="+levelToString[ll], podName, ns)
				}
			}
			if err != nil {
				return err
			}
			_, _ = fmt.Fprint(c.OutOrStdout(), resp)
			return nil
		},
	}

	levelListString := fmt.Sprintf("[%s, %s, %s, %s, %s, %s, %s]",
		levelToString[TraceLevel],
		levelToString[DebugLevel],
		levelToString[InfoLevel],
		levelToString[WarningLevel],
		levelToString[ErrorLevel],
		levelToString[CriticalLevel],
		levelToString[OffLevel])
	s := strings.Join(activeLoggers, ", ")
	logCmd.PersistentFlags().BoolVarP(&reset, "reset", "r", reset, "Specify if the reset log level to default value (warning).")
	logCmd.PersistentFlags().StringVar(&loggerLevelString, "level", loggerLevelString,
		fmt.Sprintf("Comma-separated minimum per-logger level of messages to output, in the form of"+
			" <logger>:<level>,<logger>:<level>,... where logger can be one of %s and level can be one of %s",
			s, levelListString))

	routeConfigCmd := &cobra.Command{
		Use:   "route <pod-name[.namespace]>",
		Short: "Retrieves route configuration for the Envoy in the specified pod",
		Long:  `Retrieve information about route configuration for the Envoy instance in the specified pod.`,
		Example: `  # Retrieve summary about route configuration for a given pod from Envoy.
  istioctl proxy-config routes <pod-name[.namespace]>

  # Retrieve route summary for route 9080.
  istioctl proxy-config route <pod-name[.namespace]> --name 9080

  # Retrieve full route dump for route 9080
  istioctl proxy-config route <pod-name[.namespace]> --name 9080 -o json
`,
		Aliases: []string{"routes", "r"},
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				cmd.Println(cmd.UsageString())
				return fmt.Errorf("route requires pod name")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			podName, ns := handlers.InferPodInfo(args[0], handlers.HandleNamespace(namespace, defaultNamespace))
			configWriter, err := setupConfigdumpEnvoyConfigWriter(podName, ns, c.OutOrStdout())
			if err != nil {
				return err
			}
			filter := configdump.RouteFilter{
				Name: routeName,
			}
			switch outputFormat {
			case summaryOutput:
				return configWriter.PrintRouteSummary(filter)
			case jsonOutput:
				return configWriter.PrintRouteDump(filter)
			default:
				return fmt.Errorf("output format %q not supported", outputFormat)
			}
		},
	}

	routeConfigCmd.PersistentFlags().StringVar(&routeName, "name", "", "Filter listeners by route name field")

	endpointConfigCmd := &cobra.Command{
		Use:   "endpoint <pod-name[.namespace]>",
		Short: "Retrieves endpoint configuration for the Envoy in the specified pod",
		Long:  `Retrieve information about endpoint configuration for the Envoy instance in the specified pod.`,
		Example: `  # Retrieve full endpoint configuration for a given pod from Envoy.
  istioctl proxy-config endpoint <pod-name[.namespace]>

  # Retrieve endpoint summary for endpoint with port 9080.
  istioctl proxy-config endpoint <pod-name[.namespace]> --port 9080

  # Retrieve full endpoint with a address (172.17.0.2).
  istioctl proxy-config endpoint <pod-name[.namespace]> --address 172.17.0.2 -o json

  # Retrieve full endpoint with a cluster name (outbound|9411||zipkin.istio-system.svc.cluster.local).
  istioctl proxy-config endpoint <pod-name[.namespace]> --cluster "outbound|9411||zipkin.istio-system.svc.cluster.local" -o json
  # Retrieve full endpoint with the status (healthy).
  istioctl proxy-config endpoint <pod-name[.namespace]> --status healthy -ojson
`,
		Aliases: []string{"endpoints", "ep"},
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				cmd.Println(cmd.UsageString())
				return fmt.Errorf("endpoint requires pod name")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			podName, ns := handlers.InferPodInfo(args[0], handlers.HandleNamespace(namespace, defaultNamespace))
			configWriter, err := setupClustersEnvoyConfigWriter(podName, ns, c.OutOrStdout())
			if err != nil {
				return err
			}

			filter := clusters.EndpointFilter{
				Address: address,
				Port:    uint32(port),
				Cluster: clusterName,
				Status:  status,
			}

			switch outputFormat {
			case summaryOutput:
				return configWriter.PrintEndpointsSummary(filter)
			case jsonOutput:
				return configWriter.PrintEndpoints(filter)
			default:
				return fmt.Errorf("output format %q not supported", outputFormat)
			}
		},
	}

	endpointConfigCmd.PersistentFlags().StringVar(&address, "address", "", "Filter endpoints by address field")
	endpointConfigCmd.PersistentFlags().IntVar(&port, "port", 0, "Filter endpoints by Port field")
	endpointConfigCmd.PersistentFlags().StringVar(&clusterName, "cluster", "", "Filter endpoints by cluster name field")
	endpointConfigCmd.PersistentFlags().StringVar(&status, "status", "", "Filter endpoints by status field")

	bootstrapConfigCmd := &cobra.Command{
		Use:   "bootstrap <pod-name[.namespace]>",
		Short: "Retrieves bootstrap configuration for the Envoy in the specified pod",
		Long:  `Retrieve information about bootstrap configuration for the Envoy instance in the specified pod.`,
		Example: `  # Retrieve full bootstrap configuration for a given pod from Envoy.
  istioctl proxy-config bootstrap <pod-name[.namespace]>
`,
		Aliases: []string{"b"},
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				cmd.Println(cmd.UsageString())
				return fmt.Errorf("bootstrap requires pod name")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			podName, ns := handlers.InferPodInfo(args[0], handlers.HandleNamespace(namespace, defaultNamespace))
			configWriter, err := setupConfigdumpEnvoyConfigWriter(podName, ns, c.OutOrStdout())
			if err != nil {
				return err
			}
			return configWriter.PrintBootstrapDump()
		},
	}

	secretConfigCmd := &cobra.Command{
		Use:   "secret <pod-name[.namespace]>",
		Short: "(experimental) Retrieves secret configuration for the Envoy in the specified pod",
		Long:  `(experimental) Retrieve information about secret configuration for the Envoy instance in the specified pod.`,
		Example: `  # Retrieve full secret configuration for a given pod from Envoy.
  istioctl proxy-config secret <pod-name[.namespace]>

THIS COMMAND IS STILL UNDER ACTIVE DEVELOPMENT AND NOT READY FOR PRODUCTION USE.
`,
		Aliases: []string{"s"},
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				cmd.Println(cmd.UsageString())
				return fmt.Errorf("secret requires pod name")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			podName, ns := handlers.InferPodInfo(args[0], handlers.HandleNamespace(namespace, defaultNamespace))
			configWriter, err := setupConfigdumpEnvoyConfigWriter(podName, ns, c.OutOrStdout())
			if err != nil {
				return err
			}
			switch outputFormat {
			case summaryOutput:
				return configWriter.PrintSecretSummary()
			case jsonOutput:
				return configWriter.PrintSecretDump()
			default:
				return fmt.Errorf("output format %q not supported", outputFormat)
			}
		},
	}

	configCmd.AddCommand(
		clusterConfigCmd, listenerConfigCmd, logCmd, routeConfigCmd, bootstrapConfigCmd, endpointConfigCmd, secretConfigCmd)

	return configCmd
}
