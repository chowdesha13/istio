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

package v1alpha3

import (
	"testing"

	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	fileaccesslog "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	grpcaccesslog "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	httppb "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	"github.com/envoyproxy/go-control-plane/pkg/conversion"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"istio.io/istio/pkg/test/util/assert"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pilot/test/xdstest"
	"istio.io/istio/pkg/util/protomarshal"
)

func TestListenerAccessLog(t *testing.T) {
	defaultFormatJSON, _ := protomarshal.ToJSON(EnvoyJSONLogFormatIstio)

	for _, tc := range []struct {
		name       string
		encoding   meshconfig.MeshConfig_AccessLogEncoding
		format     string
		wantFormat string
	}{
		{
			name:       "valid json object",
			encoding:   meshconfig.MeshConfig_JSON,
			format:     `{"foo": "bar"}`,
			wantFormat: `{"foo":"bar"}`,
		},
		{
			name:       "valid nested json object",
			encoding:   meshconfig.MeshConfig_JSON,
			format:     `{"foo": {"bar": "ha"}}`,
			wantFormat: `{"foo":{"bar":"ha"}}`,
		},
		{
			name:       "invalid json object",
			encoding:   meshconfig.MeshConfig_JSON,
			format:     `foo`,
			wantFormat: defaultFormatJSON,
		},
		{
			name:       "incorrect json type",
			encoding:   meshconfig.MeshConfig_JSON,
			format:     `[]`,
			wantFormat: defaultFormatJSON,
		},
		{
			name:       "incorrect json type",
			encoding:   meshconfig.MeshConfig_JSON,
			format:     `"{}"`,
			wantFormat: defaultFormatJSON,
		},
		{
			name:       "default json format",
			encoding:   meshconfig.MeshConfig_JSON,
			wantFormat: defaultFormatJSON,
		},
		{
			name:       "default text format",
			encoding:   meshconfig.MeshConfig_TEXT,
			wantFormat: EnvoyTextLogFormat,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Update MeshConfig
			env := buildListenerEnv(nil)
			env.Mesh().AccessLogFile = "foo"
			env.Mesh().AccessLogEncoding = tc.encoding
			env.Mesh().AccessLogFormat = tc.format

			// Trigger MeshConfig change and validate that access log is recomputed.
			accessLogBuilder.reset()

			// Validate that access log filter uses the new format.
			listeners := buildAllListeners(&fakePlugin{}, env)
			for _, l := range listeners {
				if l.AccessLog[0].Filter == nil {
					t.Fatal("expected filter config in listener access log configuration")
				}
				// Verify listener access log.
				verify(t, tc.encoding, l.AccessLog[0], tc.wantFormat)

				for _, fc := range l.FilterChains {
					for _, filter := range fc.Filters {
						switch filter.Name {
						case wellknown.TCPProxy:
							tcpConfig := &tcp.TcpProxy{}
							if err := filter.GetTypedConfig().UnmarshalTo(tcpConfig); err != nil {
								t.Fatal(err)
							}
							if tcpConfig.GetCluster() == util.BlackHoleCluster {
								// Ignore the tcp_proxy filter with black hole cluster that just doesn't have access log.
								continue
							}
							if len(tcpConfig.AccessLog) < 1 {
								t.Fatalf("tcp_proxy want at least 1 access log, got 0")
							}
							// Verify tcp proxy access log.
							verify(t, tc.encoding, tcpConfig.AccessLog[0], tc.wantFormat)
						case wellknown.HTTPConnectionManager:
							httpConfig := &httppb.HttpConnectionManager{}
							if err := filter.GetTypedConfig().UnmarshalTo(httpConfig); err != nil {
								t.Fatal(err)
							}
							if len(httpConfig.AccessLog) < 1 {
								t.Fatalf("http_connection_manager want at least 1 access log, got 0")
							}
							// Verify HTTP connection manager access log.
							verify(t, tc.encoding, httpConfig.AccessLog[0], tc.wantFormat)
						}
					}
				}
			}
		})
	}
}

func verify(t *testing.T, encoding meshconfig.MeshConfig_AccessLogEncoding, got *accesslog.AccessLog, wantFormat string) {
	cfg, _ := conversion.MessageToStruct(got.GetTypedConfig())
	if encoding == meshconfig.MeshConfig_JSON {
		jsonFormat := cfg.GetFields()["log_format"].GetStructValue().GetFields()["json_format"]
		jsonFormatString, _ := protomarshal.ToJSON(jsonFormat)
		if jsonFormatString != wantFormat {
			t.Errorf("\nwant: %s\n got: %s", wantFormat, jsonFormatString)
		}
	} else {
		textFormatString := cfg.GetFields()["log_format"].GetStructValue().GetFields()["text_format_source"].GetStructValue().
			GetFields()["inline_string"].GetStringValue()
		if textFormatString != wantFormat {
			t.Errorf("\nwant: %s\n got: %s", wantFormat, textFormatString)
		}
	}
}

func TestBuildAccessLogFromTelemetry(t *testing.T) {
	singleCfg := &model.LoggingConfig{
		Providers: []*meshconfig.MeshConfig_ExtensionProvider{
			{
				Name: "",
				Provider: &meshconfig.MeshConfig_ExtensionProvider_EnvoyFileAccessLog{
					EnvoyFileAccessLog: &meshconfig.MeshConfig_ExtensionProvider_EnvoyFileAccessLogProvider{
						Path: "/dev/stdout",
					},
				},
			},
		},
	}

	multiCfg := &model.LoggingConfig{
		Providers: []*meshconfig.MeshConfig_ExtensionProvider{
			{
				Name: "stdout",
				Provider: &meshconfig.MeshConfig_ExtensionProvider_EnvoyFileAccessLog{
					EnvoyFileAccessLog: &meshconfig.MeshConfig_ExtensionProvider_EnvoyFileAccessLogProvider{
						Path: "/dev/stdout",
					},
				},
			},
			{
				Name: "stderr",
				Provider: &meshconfig.MeshConfig_ExtensionProvider_EnvoyFileAccessLog{
					EnvoyFileAccessLog: &meshconfig.MeshConfig_ExtensionProvider_EnvoyFileAccessLogProvider{
						Path: "/dev/stderr",
					},
				},
			},
		},
	}

	grpcCfg := &model.LoggingConfig{
		Providers: []*meshconfig.MeshConfig_ExtensionProvider{
			{
				Name: "stdout",
				Provider: &meshconfig.MeshConfig_ExtensionProvider_EnvoyFileAccessLog{
					EnvoyFileAccessLog: &meshconfig.MeshConfig_ExtensionProvider_EnvoyFileAccessLogProvider{
						Path: "/dev/stdout",
					},
				},
			},
			{
				Name: "grpc-http-als",
				Provider: &meshconfig.MeshConfig_ExtensionProvider_EnvoyHttpAls{
					EnvoyHttpAls: &meshconfig.MeshConfig_ExtensionProvider_EnvoyHttpGrpcV3LogProvider{
						LogName:                         "grpc-otel-als",
						Service:                         "otel.foo.svc.cluster.local",
						Port:                            9811,
						AdditionalRequestHeadersToLog:   []string{"fake-request-header1"},
						AdditionalResponseHeadersToLog:  []string{"fake-response-header1"},
						AdditionalResponseTrailersToLog: []string{"fake-response-trailer1"},
					},
				},
			},
		},
	}

	grpcBacdEndClusterName := "outbound|9811||otel.foo.svc.cluster.local"
	clusterLookupFn = func(push *model.PushContext, service string, port int) (hostname string, cluster string, err error) {
		return "", grpcBacdEndClusterName, nil
	}

	stdout := &fileaccesslog.FileAccessLog{
		Path: "/dev/stdout",
		AccessLogFormat: &fileaccesslog.FileAccessLog_LogFormat{
			LogFormat: &core.SubstitutionFormatString{
				Format: &core.SubstitutionFormatString_TextFormatSource{
					TextFormatSource: &core.DataSource{
						Specifier: &core.DataSource_InlineString{
							InlineString: EnvoyTextLogFormat,
						},
					},
				},
			},
		},
	}

	errout := &fileaccesslog.FileAccessLog{
		Path: "/dev/stderr",
		AccessLogFormat: &fileaccesslog.FileAccessLog_LogFormat{
			LogFormat: &core.SubstitutionFormatString{
				Format: &core.SubstitutionFormatString_TextFormatSource{
					TextFormatSource: &core.DataSource{
						Specifier: &core.DataSource_InlineString{
							InlineString: EnvoyTextLogFormat,
						},
					},
				},
			},
		},
	}

	grpcout := &grpcaccesslog.HttpGrpcAccessLogConfig{
		CommonConfig: &grpcaccesslog.CommonGrpcAccessLogConfig{
			LogName: "grpc-otel-als",
			GrpcService: &core.GrpcService{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
						ClusterName: grpcBacdEndClusterName,
					},
				},
			},
			TransportApiVersion:     core.ApiVersion_V3,
			FilterStateObjectsToLog: envoyWasmStateToLog,
		},
		AdditionalRequestHeadersToLog:   []string{"fake-request-header1"},
		AdditionalResponseHeadersToLog:  []string{"fake-response-header1"},
		AdditionalResponseTrailersToLog: []string{"fake-response-trailer1"},
	}

	for _, tc := range []struct {
		name        string
		ctx         *model.PushContext
		meshConfig  *meshconfig.MeshConfig
		spec        *model.LoggingConfig
		forListener bool

		expected []*accesslog.AccessLog
	}{
		{
			name: "single",
			meshConfig: &meshconfig.MeshConfig{
				AccessLogEncoding: meshconfig.MeshConfig_TEXT,
			},
			spec:        singleCfg,
			forListener: false,
			expected: []*accesslog.AccessLog{
				{
					Name:       wellknown.FileAccessLog,
					ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: util.MessageToAny(stdout)},
				},
			},
		},
		{
			name: "single-listener",
			meshConfig: &meshconfig.MeshConfig{
				AccessLogEncoding: meshconfig.MeshConfig_TEXT,
			},
			spec:        singleCfg,
			forListener: true,
			expected: []*accesslog.AccessLog{
				{
					Name:       wellknown.FileAccessLog,
					Filter:     addAccessLogFilter(),
					ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: util.MessageToAny(stdout)},
				},
			},
		},
		{
			name: "multi",
			meshConfig: &meshconfig.MeshConfig{
				AccessLogEncoding: meshconfig.MeshConfig_TEXT,
			},
			spec:        multiCfg,
			forListener: false,
			expected: []*accesslog.AccessLog{
				{
					Name:       wellknown.FileAccessLog,
					ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: util.MessageToAny(stdout)},
				},
				{
					Name:       wellknown.FileAccessLog,
					ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: util.MessageToAny(errout)},
				},
			},
		},
		{
			name: "multi-listener",
			meshConfig: &meshconfig.MeshConfig{
				AccessLogEncoding: meshconfig.MeshConfig_TEXT,
			},
			spec:        multiCfg,
			forListener: true,
			expected: []*accesslog.AccessLog{
				{
					Name:       wellknown.FileAccessLog,
					Filter:     addAccessLogFilter(),
					ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: util.MessageToAny(stdout)},
				},
				{
					Name:       wellknown.FileAccessLog,
					Filter:     addAccessLogFilter(),
					ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: util.MessageToAny(errout)},
				},
			},
		},
		{
			name: "grpc-als",
			spec: grpcCfg,
			meshConfig: &meshconfig.MeshConfig{
				AccessLogEncoding: meshconfig.MeshConfig_TEXT,
			},
			forListener: false,
			expected: []*accesslog.AccessLog{
				{
					Name:       wellknown.FileAccessLog,
					ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: util.MessageToAny(stdout)},
				},
				{
					Name:       wellknown.HTTPGRPCAccessLog,
					ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: util.MessageToAny(grpcout)},
				},
			},
		},
	} {
		got := buildAccessLogFromTelemetry(tc.ctx, tc.meshConfig, tc.spec, tc.forListener)

		assert.Equal(t, tc.expected, got)
	}
}

func TestAccessLogPatch(t *testing.T) {
	// Regression test for https://github.com/istio/istio/issues/35778
	cg := NewConfigGenTest(t, TestOptions{
		Configs:        nil,
		ConfigPointers: nil,
		ConfigString: `
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: access-log-format
  namespace: default
spec:
  configPatches:
  - applyTo: NETWORK_FILTER
    match:
      context: ANY
      listener:
        filterChain:
          filter:
            name: envoy.filters.network.tcp_proxy
    patch:
      operation: MERGE
      value:
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          access_log:
          - name: envoy.access_loggers.stream
            typed_config:
              '@type': type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
              log_format:
                json_format:
                  envoyproxy_authority: '%REQ(:AUTHORITY)%'
`,
	})

	proxy := cg.SetupProxy(nil)
	l1 := cg.Listeners(proxy)
	l2 := cg.Listeners(proxy)
	// Make sure it doesn't change between patches
	if d := cmp.Diff(l1, l2, protocmp.Transform()); d != "" {
		t.Fatal(d)
	}
	// Make sure we have exactly 1 access log
	fc := xdstest.ExtractFilterChain("virtualOutbound-blackhole", xdstest.ExtractListener("virtualOutbound", l1))
	if len(xdstest.ExtractTCPProxy(t, fc).GetAccessLog()) != 1 {
		t.Fatalf("unexpected access log: %v", xdstest.ExtractTCPProxy(t, fc).GetAccessLog())
	}
}
