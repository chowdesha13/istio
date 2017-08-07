#!/bin/bash

# Copyright 2017 Istio Authors

#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at

#       http://www.apache.org/licenses/LICENSE-2.0

#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


#######################################
# Postsubmit script triggered by Prow. #
#######################################

# Exit immediately for non zero status
set -e
# Check unset variables
set -u
# Print commands
set -x

E2E_ARGS=()

if [ "${CI}" == 'bootstrap' ]; then
  # Test harness will checkout code to directory $GOPATH/src/github.com/istio/istio
  # but we depend on being at path $GOPATH/src/istio.io/istio for imports
  ln -sf ${GOPATH}/src/github.com/istio ${GOPATH}/src/istio.io
  cd ${GOPATH}/src/istio.io/istio

  # bootsrap upload all artifacts in _artifacts to the log bucket.
  ARTIFACTS_DIR="${GOPATH}/src/istio.io/istio/_artifacts"
  LOG_HOST="stackdriver"
  PROJ_ID="istio-testing"
  E2E_ARGS+=(--test_logs_path="${ARTIFACTS_DIR}" --log_provider=${LOG_HOST} --project_id=${PROJ_ID})
fi

echo 'Running e2e no rbac, no auth Tests'
./tests/e2e.sh ${E2E_ARGS[@]}
