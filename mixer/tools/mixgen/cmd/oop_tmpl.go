package cmd

var oopMainTempl = `// Copyright 2018 Istio Authors
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

// THIS FILE IS AUTOMATICALLY GENERATED.

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"{{.PackagePath}}/server"
)

// Args represents args consumed by OOP adapter.
type Args struct {
	// Port to start the grpc adapter on
	AdapterPort uint16

	// Size of adapter API worker pool
	APIWorkerPoolSize int

	// TLS server cert and credential
	Cert *server.Cert
}

func defaultArgs() *Args {
	return &Args{
		AdapterPort:       uint16(8080),
		APIWorkerPoolSize: 1024,
		Cert:              server.DefaultCertOption(),
	}
}

// GetCmd returns the cobra command-tree.
func GetCmd(_ []string) *cobra.Command {
	sa := defaultArgs()
	cmd := &cobra.Command{
		Use:   "{{.AdapterName}}",
		Short: "Istio {{.AdapterName}} out of process adapter.",
		Run: func(cmd *cobra.Command, args []string) {
			runServer(sa)
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("'%s' is an invalid argument", args[0])
			}
			return nil
		},
	}

	f := cmd.PersistentFlags()
	f.Uint16VarP(&sa.AdapterPort, "port", "p", sa.AdapterPort,
		"TCP port to use for gRPC Adapter API")
	f.IntVarP(&sa.APIWorkerPoolSize, "apiPool", "a", sa.APIWorkerPoolSize,
		"Size of adapter API worker pool")
	sa.Cert.AttachCobraFlags(cmd)
	return cmd
}

func main() {
	cmd := GetCmd(os.Args[1:])
	if err := cmd.Execute(); err != nil {
		os.Exit(-1)
	}
}

func runServer(args *Args) {
	s, err := server.NewStackdriverNoSessionServer(args.AdapterPort, args.APIWorkerPoolSize, args.Cert)
	if err != nil {
		fmt.Printf("unable to start server: %v", err)
		os.Exit(-1)
	}

	s.Run()
	s.Wait()
}
`

var noSessionServerTempl = `// Copyright 2018 Istio Authors
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

// THIS FILE IS AUTOMATICALLY GENERATED.

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"sync"

	"google.golang.org/grpc"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/credentials"
	$$additional_imports$$

	adptModel "istio.io/api/mixer/adapter/model/v1beta1"
	"istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/pkg/pool"
	"istio.io/istio/mixer/pkg/runtime/handler"
	{{- range .TemplatePackages}}
    "{{.}}"
	{{- end}}
	{{.AdapterName}} "{{.AdapterPackage}}"
	{{if ne .AdapterConfigPackage "" -}}
	config "{{.AdapterConfigPackage}}"
	{{end -}}
)

type (
	// Server is basic server interface
	Server interface {
		Addr() string
		Close() error
		Run()
	}

	// NoSession models nosession adapter backend.
	NoSession struct {
		listener net.Listener
		shutdown chan error
		server   *grpc.Server

		builder     adapter.HandlerBuilder
		env         adapter.Env
		builderLock sync.RWMutex
		handlerMap map[string]adapter.Handler
	}

	// Cert includes cert config for adapter server
	Cert struct {
		credentialFile    string
		privateKeyFile    string
		caCertificateFile string
		enableTLS         bool
		requireClientAuth bool
	}
)

// DefaultCertOption return default cert option for adapter service
func DefaultCertOption() *Cert {
	return &Cert{
		credentialFile:    "/etc/certs/cert-chain.pem",
		privateKeyFile:    "/etc/certs/key.pem",
		caCertificateFile: "/etc/certs/root-cert.pem",
		enableTLS:         false,
		requireClientAuth: false,
	}
}

// AttachCobraFlags attach certs related flags.
func (c *Cert) AttachCobraFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&c.credentialFile, "certFile", "", c.credentialFile,
		"The location of the certificate file for TLS")
	cmd.PersistentFlags().StringVarP(&c.privateKeyFile, "keyFile", "", c.privateKeyFile,
		"The location of the key file for TLS")
	cmd.PersistentFlags().StringVarP(&c.caCertificateFile, "caCertFile", "", c.caCertificateFile,
		"The location of the certificate file for the root certificate authority")
	cmd.PersistentFlags().BoolVarP(&c.enableTLS, "enableTLS", "", c.enableTLS,
		"")
	cmd.PersistentFlags().BoolVarP(&c.requireClientAuth, "requireClientAuth", "", c.requireClientAuth,
		"")
}
{{range .Models}}
var _ {{.GoPackageName}}.Handle{{.InterfaceName -}}ServiceServer = &NoSession{}
{{- end}}

func (s *NoSession) updateHandlers(rawcfg []byte) (adapter.Handler, error) {
	{{if ne .AdapterConfigPackage "" -}}
	cfg := &config.Params{}

	if err := cfg.Unmarshal(rawcfg); err != nil {
		return nil, err
	}

	s.builderLock.Lock()
	defer s.builderLock.Unlock()
	if handler, ok := s.handlerMap[string(rawcfg)]; ok {
		return handler, nil
	}

	s.env.Logger().Infof("Loaded handler with: %v", cfg)
	s.builder.SetAdapterConfig(cfg)
	{{end}}

	if ce := s.builder.Validate(); ce != nil {
		return nil, ce
	}

	h, err := s.builder.Build(context.Background(), s.env)
	if err != nil {
		s.env.Logger().Errorf("could not build: %v", err)
		return nil, err
	}
	s.handlerMap[string(rawcfg)] = h
	return h, nil
}
{{range .Models}}
func (s *NoSession) get{{.InterfaceName -}}Handler(rawcfg []byte) ({{.GoPackageName}}.Handler, error) {
	s.builderLock.RLock()
	if handler, ok := s.handlerMap[string(rawcfg)]; ok {
		h := handler.({{.GoPackageName}}.Handler)
		s.builderLock.RUnlock()
		return h, nil
	}
	s.builderLock.RUnlock()
	h, err := s.updateHandlers(rawcfg)
	if err != nil {
		return nil, err
	}

	// establish session
	return h.({{.GoPackageName}}.Handler), nil
}
{{end}}

{{define "transform"}}
		{{range .Fields -}}
		{{if .ProtoType.IsRepeated -}}
		{{if .ProtoType.IsResourceMessage -}}
		{{.GoName}}: transform{{FindPackage .}}{{TrimGoType .GoType.Name}}MsgSlice(inst.{{.GoName}}),
		{{else if eq .ProtoType.Name "istio.policy.v1beta1.Value" -}}
		{{.GoName}}: transformValueSlice(inst.{{.GoName}}),
		{{else if or (eq .ProtoType.Name "string") (eq .ProtoType.Name "int") (eq .ProtoType.Name "double") (eq .ProtoType.Name "bool") -}}
		{{.GoName}}: inst.{{.GoName -}},
		{{end -}}
		{{else if .ProtoType.IsMap -}}
		{{if .ProtoType.MapValue.IsResourceMessage -}}
		{{.GoName}}: transform{{FindPackage .}}{{TrimGoType .ProtoType.MapValue.Name}}MsgMap(inst.{{.GoName}}),
		{{else if eq .ProtoType.MapValue.Name "istio.policy.v1beta1.Value" -}}
		{{.GoName}}: transformValueMap(inst.{{.GoName}}),
		{{else if eq .ProtoType.MapValue.Name "string" -}}
		{{.GoName}}: inst.{{.GoName}},
		{{else if eq .ProtoType.MapValue.Name "int" -}}
		{{.GoName}}: inst.{{.GoName}},
		{{else if eq .ProtoType.MapValue.Name "double" -}}
		{{.GoName}}: inst.{{.GoName}},
		{{else if eq .ProtoType.MapValue.Name "bool" -}}
		{{.GoName}}: inst.{{.GoName}},
		{{end -}}
		{{else if .ProtoType.IsResourceMessage -}}
		{{.GoName}}: transform{{FindPackage .}}{{TrimGoType .GoType.Name}}Msg(inst.{{.GoName}}),
		{{else if eq .ProtoType.Name "istio.policy.v1beta1.Value" -}}
		{{.GoName}}: transformValue(inst.{{.GoName}}.GetValue()),
		{{else if eq .ProtoType.Name "istio.policy.v1beta1.TimeStamp" -}}
		{{.GoName}}: tmp{{.GoName}},
		{{else if eq .ProtoType.Name "istio.policy.v1beta1.Duration" -}}
		{{.GoName}}: tmp{{.GoName}},
		{{else if eq .ProtoType.Name "istio.policy.v1beta1.IPAddress" -}}
		{{.GoName}}: inst.{{.GoName}}.Value,
		{{else if eq .ProtoType.Name "istio.policy.v1beta1.DNSName" -}}
		{{.GoName}}: adapter.DNSName(inst.{{.GoName}}.Value),
		{{else if eq .ProtoType.Name "istio.policy.v1beta1.EmailAddress" -}}
		{{.GoName}}: adapter.EmailAddress(inst.{{.GoName}}.Value),
		{{else if eq .ProtoType.Name "istio.policy.v1beta1.Uri" -}}
		{{.GoName}}: adapter.URI(inst.{{.GoName}}.Value),
		{{else -}}
		{{.GoName}}: inst.{{.GoName}},
		{{end -}}
		{{end -}}
{{end -}}

{{range .Models -}}
{{$gp := .GoPackageName -}}
{{range .ResourceMessages -}}
func transform{{$gp}}{{.Name}}Msg(inst *{{$gp}}.{{.Name}}Msg) *{{$gp}}.{{.Name}} {
	{{range .Fields -}}
	{{if eq .ProtoType.Name "istio.policy.v1beta1.TimeStamp" -}}
	{{AddProtoToImpt -}}
	tmp{{.GoName}}, err := proto.TimestampFromProto(inst.{{.GoName}}.GetValue())
	if err != nil {
		return nil
	}
	{{else if eq .ProtoType.Name "istio.policy.v1beta1.Duration" -}}
	{{AddProtoToImpt -}}
	tmp{{.GoName}}, err := proto.DurationFromProto(inst.{{.GoName}}.GetValue())
	if err != nil {
		return nil
	}
	{{end -}}
	{{end -}}
	return &{{$gp}}.{{.Name}}{
		{{template "transform" .}}
	}
}

func transform{{$gp}}{{.Name}}MsgSlice(insts []*{{$gp}}.{{.Name}}Msg) []*{{$gp}}.{{.Name}} {
	ret := make([]*{{$gp}}.{{.Name}}, 0, len(insts))
	for _, inst := range insts {
		ret = append(ret, transform{{$gp}}{{.Name}}Msg(inst))
	}
	return ret
}

func transform{{$gp}}{{.Name}}MsgMap(insts map[string]*{{$gp}}.{{.Name}}Msg) map[string]*{{$gp}}.{{.Name}} {
	ret := make(map[string]*{{$gp}}.{{.Name}})
	for k, inst := range insts {
		ret[k] = transform{{$gp}}{{.Name}}Msg(inst)
	}
	return ret
}
{{end -}}
{{end -}}

{{range .Models}}
{{if eq .VarietyName "TEMPLATE_VARIETY_REPORT" -}}
func {{.GoPackageName}}Instances(in []*{{.GoPackageName}}.InstanceMsg) []*{{.GoPackageName}}.Instance {
	out := make([]*{{.GoPackageName}}.Instance, 0, len(in))

	for _, inst := range in {
		{{range .TemplateMessage.Fields -}}
		{{if eq .ProtoType.Name "istio.policy.v1beta1.TimeStamp" -}}
		{{AddProtoToImpt -}}
		tmp{{.GoName}}, err := proto.TimestampFromProto(inst.{{.GoName}}.GetValue())
		if err != nil {
			continue
		}
		{{else if eq .ProtoType.Name "istio.policy.v1beta1.Duration" -}}
		{{AddProtoToImpt -}}
		tmp{{.GoName}}, err := proto.DurationFromProto(inst.{{.GoName}}.GetValue())
		if err != nil {
			continue
		}
		{{end -}}
		{{end -}}
		out = append(out, &{{.GoPackageName}}.Instance{
			Name: inst.Name,
			{{template "transform" .TemplateMessage}}
		})
	}
	return out
}
{{else if or (eq .VarietyName "TEMPLATE_VARIETY_CHECK") (eq .VarietyName "TEMPLATE_VARIETY_QUOTA") -}}
func {{.GoPackageName}}Instance(inst *{{.GoPackageName}}.InstanceMsg) *{{.GoPackageName}}.Instance {
	{{range .TemplateMessage.Fields -}}
	{{if eq .ProtoType.Name "istio.policy.v1beta1.TimeStamp" -}}
	{{AddProtoToImpt -}}
	tmp{{.GoName}}, err := proto.TimestampFromProto(inst.{{.GoName}}.GetValue())
	if err != nil {
		return nil
	}
	{{else if eq .ProtoType.Name "istio.policy.v1beta1.Duration" -}}
	{{AddProtoToImpt -}}
	tmp{{.GoName}}, err := proto.DurationFromProto(inst.{{.GoName}}.GetValue())
	if err != nil {
		return nil
	}
	{{end -}}
	{{end -}}
	return &{{.GoPackageName}}.Instance{
		Name: inst.Name,
		{{template "transform" .TemplateMessage}}
	}
}
{{end -}}
{{end}}

func transformValueMap(in map[string]*v1beta1.Value) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = transformValue(v.GetValue())
	}
	return out
}

func transformValueSlice(in []interface{}) []interface{} {
	out := make([]interface{}, 0, len(in))
	for _, inst := range in {
		out = append(out, transformValue(inst))
	}
	return out
}

func transformValue(in interface{}) interface{} {
	switch t := in.(type) {
	case *v1beta1.Value_StringValue:
		return t.StringValue
	case *v1beta1.Value_Int64Value:
		return t.Int64Value
	case *v1beta1.Value_DoubleValue:
		return t.DoubleValue
	case *v1beta1.Value_BoolValue:
		return t.BoolValue
	case *v1beta1.Value_IpAddressValue:
		return t.IpAddressValue.Value
	case *v1beta1.Value_EmailAddressValue:
		return t.EmailAddressValue.Value
	case *v1beta1.Value_UriValue:
		return t.UriValue.Value
	default:
		return fmt.Sprintf("%v", in)
	}
}

{{range .Models}}
// Handle{{.InterfaceName}} handles '{{.InterfaceName}}' instances.
{{if eq .VarietyName "TEMPLATE_VARIETY_REPORT" -}}
func (s *NoSession) Handle{{.InterfaceName -}}(ctx context.Context, r *{{.GoPackageName}}.Handle{{.InterfaceName -}}Request) (*adptModel.ReportResult, error) {
	h, err := s.get{{.InterfaceName -}}Handler(r.AdapterConfig.Value)
	if err != nil {
		return nil, err
	}

	if err = h.Handle{{.InterfaceName -}}(ctx, {{.GoPackageName}}Instances(r.Instances)); err != nil {
		s.env.Logger().Errorf("Could not process: %v", err)
		return nil, err
	}

	return &adptModel.ReportResult{}, nil
}
{{else if eq .VarietyName "TEMPLATE_VARIETY_CHECK" -}}
func (s *NoSession) Handle{{.InterfaceName -}}(ctx context.Context, r *{{.GoPackageName}}.Handle{{.InterfaceName -}}Request) (*adptModel.CheckResult, error) {
	h, err := s.get{{.InterfaceName -}}Handler(r.AdapterConfig.Value)
	if err != nil {
		return nil, err
	}
	inst := {{.GoPackageName}}Instance(r.Instance)
	if inst == nil {
		return nil, fmt.Errorf("cannot transform instance")
	}
	cr, err := h.Handle{{.InterfaceName -}}(ctx, inst)
	if err != nil {
		s.env.Logger().Errorf("Could not process: %v", err)
		return nil, err
	}
	return &adptModel.CheckResult{
		Status:        cr.Status,
		ValidDuration: cr.ValidDuration,
		ValidUseCount: cr.ValidUseCount,
	}, nil
}
{{else if eq .VarietyName "TEMPLATE_VARIETY_QUOTA" -}}
func (s *NoSession) Handle{{.InterfaceName -}}(ctx context.Context, r *{{.GoPackageName}}.Handle{{.InterfaceName -}}Request) (*adptModel.QuotaResult, error) {
	h, err := s.get{{.InterfaceName -}}Handler(r.AdapterConfig.Value)
	if err != nil {
		return nil, err
	}

	qi := {{.GoPackageName}}Instance(r.Instance)
	resp := adptModel.QuotaResult{
		Quotas: make(map[string]adptModel.QuotaResult_Result),
	}
	for qt, p := range r.QuotaRequest.Quotas {
		qa := adapter.QuotaArgs{
			DeduplicationID: r.DedupId,
			QuotaAmount:     p.Amount,
			BestEffort:      p.BestEffort,
		}
		qr, err := h.Handle{{.InterfaceName -}}(ctx, qi, qa)
		if err != nil {
			return nil, err
		}
		resp.Quotas[qt] = adptModel.QuotaResult_Result{
			ValidDuration: qr.ValidDuration,
			GrantedAmount: qr.Amount,
		}
	}
	if err != nil {
		s.env.Logger().Errorf("Could not process: %v", err)
		return nil, err
	}
	return &resp, nil
}
{{end}}
{{end}}

// Addr returns the listening address of the server
func (s *NoSession) Addr() string {
	return s.listener.Addr().String()
}

// Run starts the server run
func (s *NoSession) Run() {
	s.shutdown = make(chan error, 1)
	go func() { //nolint:adapterlinter
		err := s.server.Serve(s.listener)

		// notify closer we're done
		s.shutdown <- err
	}()
}

// Wait waits for server to stop
func (s *NoSession) Wait() error {
	if s.shutdown == nil {
		return fmt.Errorf("server not running")
	}

	err := <-s.shutdown
	s.shutdown = nil
	return err
}

// Close gracefully shuts down the server
func (s *NoSession) Close() error {
	if s.shutdown != nil {
		s.server.GracefulStop()
		_ = s.Wait()
	}

	if s.listener != nil {
		_ = s.listener.Close()
	}

	return nil
}

func getServerTLSOption(c *Cert) (grpc.ServerOption, error) {
	certificate, err := tls.LoadX509KeyPair(
		c.credentialFile,
		c.privateKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load key cert pair.")
	}
	certPool := x509.NewCertPool()
	bs, err := ioutil.ReadFile(c.caCertificateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read client ca cert: %s", err)
	}

	ok := certPool.AppendCertsFromPEM(bs)
	if !ok {
		return nil, fmt.Errorf("failed to append client certs")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,
	}
	if c.requireClientAuth {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return grpc.Creds(credentials.NewTLS(tlsConfig)), nil
}

// New{{Capitalize .AdapterName}}NoSessionServer creates a new no session server based on given args.
func New{{Capitalize .AdapterName}}NoSessionServer(addr uint16, poolSize int, c *Cert) (*NoSession, error) {
	saddr := fmt.Sprintf(":%d", addr)

	gp := pool.NewGoroutinePool(poolSize, false)
	inf := {{.AdapterName}}.GetInfo()
	s := &NoSession{
		builder: inf.NewBuilder(),
		env:     handler.NewEnv(0, "{{.AdapterName}}-nosession", gp),
		handlerMap: make(map[string]adapter.Handler),
	}
	var err error
	if s.listener, err = net.Listen("tcp", saddr); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("unable to listen on socket: %v", err)
	}

	fmt.Printf("listening on :%v\n", s.listener.Addr())
	if c.enableTLS {
		so, err := getServerTLSOption(c)
		if err != nil {
			return nil, err
		}
		s.server = grpc.NewServer(so)
	} else {
		s.server = grpc.NewServer()
	}
	{{range .Models}}
	{{.GoPackageName}}.RegisterHandle{{.InterfaceName -}}ServiceServer(s.server, s)
	{{- end}}

	return s, nil
}
`

var makeFileTmpl = `.PHONY: build docker docker.push

build: main.go
	CGO_ENABLED=0 GOOS=linux go build -o {{.AdapterName}}adapter .
docker: {{.AdapterName}}adapter
	docker build . -t your-repo/{{.AdapterName}}adapter:0.1.0
docker.push: 
	docker push your-repo/{{.AdapterName}}adapter:0.1.0
`

var dockerFileTmpl = `FROM ubuntu:xenial

RUN apt-get -y update && apt-get --no-install-recommends -y install ca-certificates
ADD {{.AdapterName}}adapter /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/{{.AdapterName}}adapter"]
`

var helmChartTmpl = `name: {{.AdapterName}}adapter
description: Istio {{.AdapterName}} out of process adapter
version: 0.1.0
`

var helmValueTemp = `image:
  repository: your-repo
  tag: 0.1.0
  pullPolicy: Always

service:
  portNumber: 8080
`

var helmDeploymentTmpl = `apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: {{.AdapterName}}adapter
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: {{.AdapterName}}adapter
    spec:
      containers:
      - image: {{"{{ .Values.image.repository }}/"}}{{.AdapterName}}{{"adapter:{{ .Values.image.tag }}"}}
        imagePullPolicy: {{"{{ .Values.image.pullPolicy }}"}}
        name: {{.AdapterName}}adapter
        ports:
        - containerPort: {{"{{ .Values.service.portNumber }}"}}
`

var helmServiceTmpl = `apiVersion: v1
kind: Service
metadata:
  name: {{.AdapterName}}adapter
  labels:
    app: {{.AdapterName}}adapter
spec:
  ports:
  - name: http
    port: {{"{{ .Values.service.portNumber }}"}}
  selector:
    app: {{.AdapterName}}adapter
`
