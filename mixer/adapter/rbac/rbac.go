// Copyright 2018 Istio Authors.
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

//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -f mixer/adapter/rbac/config/config.proto

package rbac

import (
	"context"

	"github.com/gogo/protobuf/proto"

	rbacproto "istio.io/api/rbac/v1alpha1"
	"istio.io/istio/mixer/adapter/rbac/config"
	"istio.io/istio/mixer/pkg/adapter"
	mixerconfig "istio.io/istio/mixer/pkg/config"
	"istio.io/istio/mixer/pkg/config/store"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/istio/mixer/template/authorization"
)

type (
	builder struct {
		adapterConfig *config.Params
	}
	handler struct {
		rbac Rbac
		env  adapter.Env
	}
)

// ServiceRoleKind defines the config kind name of ServiceRole.
const serviceRoleKind = "ServiceRole"

// ServiceRoleBindingKind defines the config kind name of ServiceRoleBinding.
const serviceRoleBindingKind = "ServiceRoleBinding"

///////////////// Configuration-time Methods ///////////////

func (b *builder) SetAdapterConfig(cfg adapter.Config) {
	b.adapterConfig = cfg.(*config.Params)
}

func (b *builder) Validate() (ce *adapter.ConfigErrors) {
	return
}

func (b *builder) SetAuthorizationTypes(types map[string]*authorization.Type) {}

func (b *builder) Build(ctx context.Context, env adapter.Env) (adapter.Handler, error) {
	reg := store.NewRegistry(mixerconfig.StoreInventory()...)
	s, err := reg.NewStore(b.adapterConfig.ConfigStoreUrl)
	if err != nil {
		env.Logger().Errorf("unable to connect to the configuration server: %v", err)
		return nil, err
	}
	r := &RbacStore{}
	err = startController(s, r, env)
	if err != nil {
		env.Logger().Errorf("unable to start controller: %v", err)
		return nil, err
	}

	return &handler{rbac: r, env: env}, nil
}

// startController creates a controller from the given params.
func startController(s store.Store, r *RbacStore, env adapter.Env) error {
	data, watchChan, err := startWatch(s)
	if err != nil {
		env.Logger().Errorf("Error while starting watching CRDs: %v", err)
		return err
	}

	c := &controller{
		configState: data,
		rbacStore:   r,
	}

	c.processRbacRoles(env)
	go watchChanges(watchChan, c.applyEvents, env)
	return nil
}

// startWatch registers with store, initiates a watch, and returns the current config state.
func startWatch(s store.Store) (map[store.Key]*store.Resource, <-chan store.Event, error) {
	ctx := context.Background()

	kindMap := make(map[string]proto.Message)
	kindMap[serviceRoleKind] = &rbacproto.ServiceRole{}
	kindMap[serviceRoleBindingKind] = &rbacproto.ServiceRoleBinding{}

	if err := s.Init(ctx, kindMap); err != nil {
		return nil, nil, err
	}
	// create channel before listing.
	watchChan, err := s.Watch(ctx)
	if err != nil {
		return nil, nil, err
	}
	return s.List(), watchChan, nil
}

////////////////// Request-time Methods //////////////////////////
// authorization.Handler#HandleAuthorization
func (h *handler) HandleAuthorization(ctx context.Context, inst *authorization.Instance) (adapter.CheckResult, error) {
	s := status.OK
	result, err := h.rbac.CheckPermission(inst, h.env)
	if !result || err != nil {
		s = status.WithPermissionDenied("RBAC: permission denied.")
	}
	return adapter.CheckResult{
		Status: s,
	}, nil
}

// adapter.Handler#Close
func (h *handler) Close() error { return nil }

////////////////// Bootstrap //////////////////////////

// GetInfo returns the adapter.Info specific to this adapter.
func GetInfo() adapter.Info {
	return adapter.Info{
		Name:        "rbac",
		Impl:        "istio.io/istio/mixer/adapter/rbac",
		Description: "Istio RBAC adapter",
		SupportedTemplates: []string{
			authorization.TemplateName,
		},
		NewBuilder:    func() adapter.HandlerBuilder { return &builder{} },
		DefaultConfig: &config.Params{},
	}
}
