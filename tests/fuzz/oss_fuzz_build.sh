#!/bin/bash

# Copyright 2021 Istio Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cd "$SRC"
git clone --depth=1 https://github.com/AdamKorcz/go-118-fuzz-build --branch=include-all-test-files
cd go-118-fuzz-build
go build .
mv go-118-fuzz-build /root/go/bin/
cd "$SRC"/istio

set -o nounset
set -o pipefail
set -o errexit
set -x

cd "${SRC}"
git clone https://github.com/AdamKorcz/instrumentation
cd instrumentation
go run main.go --target_dir="${SRC}"/istio --check_io_length=true
cd "${SRC}"/istio

# Create empty file that imports "github.com/AdamKorcz/go-118-fuzz-build/testing"
# This is a small hack to install this dependency, since it is not used anywhere,
# and Go would therefore remove it from go.mod once we run "go mod tidy && go mod vendor".
printf "package main\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > register.go
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build="$SRC"/go-118-fuzz-build
go mod tidy

# Find all native fuzzers and compile them
# shellcheck disable=SC2016
grep --line-buffered --include '*_test.go' -Pr 'func Fuzz.*\(.* \*testing\.F' | sed -E 's/(func Fuzz(.*)\(.*)/\2/' | xargs -I{} sh -c '
  fname="$(dirname $(echo "{}" | cut -d: -f1))"
  func="Fuzz$(echo "{}" | cut -d: -f2)"
  set -x
  compile_native_go_fuzzer istio.io/istio/$fname $func $func
'

# Now compile fuzzers from tests/fuzz
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzCRDRoundtrip fuzz_crd_roundtrip
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzExtractIDs fuzz_extract_ids
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzPemCertBytestoString fuzz_pem_cert_bytes_to_string 
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzParsePemEncodedCertificateChain fuzz_parse_pem_encoded_certificate_chain 
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzUpdateVerifiedKeyCertBundleFromFile fuzz_update_verified_cert_bundle_from_file
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzJwtUtil fuzz_jwt_util
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzVerifyCertificate fuzz_verify_certificate
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzFindRootCertFromCertificateChainBytes fuzz_find_root_cert_from_certificate_chain_bytes
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzAggregateController fuzz_aggregate_controller
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzKubeCRD fuzz_kube_crd
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzWE fuzz_workload_entry
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzConfigValidation3 fuzz_config_validation_3
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzCidrRange fuzz_cidr_range
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzHeaderMatcher fuzz_header_matcher
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzHostMatcher fuzz_host_matcher
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzMetadataListMatcher fuzz_metadata_list_matcher
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzGrpcGenGenerate fuzz_grpc_gen_generate
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzConvertIngressVirtualService fuzz_convert_ingress_virtual_service
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzConvertIngressV1alpha3 fuzz_convert_ingress_v1alpha3
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzParseInputs fuzz_parse_inputs
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzConfigValidation fuzz_config_validation
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzConfigValidation2 fuzz_config_validation2
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzParseMeshNetworks fuzz_parse_mesh_networks
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzValidateMeshConfig fuzz_validate_mesh_config
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzInitContext fuzz_init_context
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzAnalyzer fuzz_analyzer
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzXds fuzz_xds
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzCompareDiff fuzz_compare_diff
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzIntoResourceFile fuzz_into_resource_file
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzBNMUnmarshalJSON fuzz_bnm_unmarshal_json
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzValidateClusters fuzz_validate_clusters
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzGalleyDiag fuzz_galley_diag
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzNewBootstrapServer fuzz_new_bootstrap_server
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzGenCSR fuzz_gen_csr
compile_go_fuzzer istio.io/istio/tests/fuzz FuzzCreateCertE2EUsingClientCertAuthenticator fuzz_create_cert_e2e_using_client_cert_authenticator

# Create seed corpora:
zip "${OUT}"/fuzz_config_validation2_seed_corpus.zip "${SRC}"/istio/tests/fuzz/testdata/FuzzConfigValidation2/seed1
zip "${OUT}"/fuzz_into_resource_file_seed_corpus.zip ./pkg/kube/inject/testdata/inject/*.yaml

# Add dictionaries
cp "${SRC}"/istio/tests/fuzz/testdata/FuzzConfigValidation2/fuzz_config_validation2.dict "${OUT}"/
mv "${SRC}"/istio/tests/fuzz/testdata/inject/fuzz_into_resource_file.dict "${OUT}"/
