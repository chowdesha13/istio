#!/bin/bash

# Copyright 2016 Istio Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Presubmit script triggered by Prow.
# - push docker images to grc.io for the integration tests.

# Separate (and parallel) jobs are doing lint, coverage, etc.

WD=$(dirname $0)
WD=$(cd $WD; pwd)
ROOT=$(dirname $WD)

# No unset vars, print commands as they're executed, and exit on any non-zero
# return code
set -u
set -x
set -e

die () {
  echo "$@"
  exit -1
}

function setup_and_export_git_sha() {
  if [ "${CI:-}" == 'bootstrap' ]; then
    # Handle prow environment and checkout
    export USER=Prow

    # Test harness will checkout code to directory $GOPATH/src/github.com/istio/istio
    # but we depend on being at path $GOPATH/src/istio.io/istio for imports
    mv ${GOPATH}/src/github.com/istio ${GOPATH}/src/istio.io
    ROOT=${GOPATH}/src/istio.io/istio
    cd ${GOPATH}/src/istio.io/istio

    # Use the provided pull head sha, from prow.
    export GIT_SHA="${PULL_PULL_SHA}"

    # check if rewrite history is present
    PR_BRANCH=$(git show-ref | grep refs/pr | awk '{print $2}')
    if [[ -z $PR_BRANCH ]];then
      echo "Could not get PR branch"
      die $(git show-ref)
    fi

    git ls-tree  $PR_BRANCH | grep .history_rewritten_20171102
    if [[ $? -ne 0 ]];then
      echo "This PR is from an out of date clone of istio.io/istio"
      die "Create a fresh clone of istio.io/istio and re-submit the PR"
    fi

    # Use volume mount from pilot-presubmit job's pod spec.
    # FIXME pilot should not need this
    ln -sf "${HOME}/.kube/config" pilot/pkg/kube/config
  else
    # Use the current commit.
    GIT_SHA="$(git rev-parse --verify HEAD)"
  fi
}

setup_and_export_git_sha

echo 'Build'
(cd ${ROOT}; make build)

# Unit tests are run against a local apiserver and etcd.
# Integration/e2e tests in the other scripts are run against GKE or real clusters.
(cd ${ROOT}; make localTestEnv test)

if [[ -n $(git diff) ]]; then
  echo "Uncommitted changes found:"
  git diff
fi

# upload images - needed by the subsequent tests
time ISTIO_DOCKER_HUB="gcr.io/istio-testing" make push HUB="gcr.io/istio-testing" TAG="${GIT_SHA}"

# run security e2e test
CERT_DIR=$(make where-is-docker-temp) ${ROOT}/security/bin/e2e.sh --hub "gcr.io/istio-testing" --tag "${GIT_SHA}"
