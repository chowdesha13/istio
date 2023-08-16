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

//go:generate sh -c "echo '//go:build !agent' > filter_types.gen.go"
//go:generate sh -c "echo '// +build !agent\n' >> filter_types.gen.go"
//go:generate sh -c "echo '// Copyright Istio Authors' >> filter_types.gen.go"
//go:generate sh -c "echo '//' >> filter_types.gen.go"
//go:generate sh -c "echo '// Licensed under the Apache License, Version 2.0 (the \"License\");' >> filter_types.gen.go"
//go:generate sh -c "echo '// you may not use this file except in compliance with the License.' >> filter_types.gen.go"
//go:generate sh -c "echo '// You may obtain a copy of the License at' >> filter_types.gen.go"
//go:generate sh -c "echo '//' >> filter_types.gen.go"
//go:generate sh -c "echo '//     http://www.apache.org/licenses/LICENSE-2.0' >> filter_types.gen.go"
//go:generate sh -c "echo '//' >> filter_types.gen.go"
//go:generate sh -c "echo '// Unless required by applicable law or agreed to in writing, software' >> filter_types.gen.go"
//go:generate sh -c "echo '// distributed under the License is distributed on an \"AS IS\" BASIS,' >> filter_types.gen.go"
//go:generate sh -c "echo '// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.' >> filter_types.gen.go"
//go:generate sh -c "echo '// See the License for the specific language governing permissions and' >> filter_types.gen.go"
//go:generate sh -c "echo '// limitations under the License.\n' >> filter_types.gen.go"
//go:generate sh -c "echo '//  GENERATED FILE -- DO NOT EDIT\n' >> filter_types.gen.go"
//go:generate sh -c "echo 'package xds\n\nimport (' >> filter_types.gen.go"
//go:generate sh -c "go list github.com/envoyproxy/go-control-plane/... | grep 'v3' | grep -v /pkg/ | xargs -I{} echo '\t_ \"{}\"' >> filter_types.gen.go"
//go:generate sh -c "echo '\n\t// Istio-specific Envoy filters' >> filter_types.gen.go"
//go:generate sh -c "go list istio.io/api/envoy/config/filter/... | grep 'v[0-9]' | xargs -I{} echo '\t_ \"{}\"' >> filter_types.gen.go"
//go:generate sh -c "echo ')' >> filter_types.gen.go"
package xds

// Import all Envoy filter types so they are registered and deserialization does not fail
// when using them in the "typed_config" attributes.
// The filter types are autogenerated by looking at all packages in go-control-plane
// As a result, this will need to be re-run when updating go-control-plane if new packages are added.
