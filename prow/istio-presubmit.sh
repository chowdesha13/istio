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

WD=$(dirname $0)
WD=$(cd $WD; pwd)
ROOT=$(dirname $WD)

#######################################
# Presubmit script triggered by Prow. #
#######################################

# Exit immediately for non zero status
set -e
# Check unset variables
set -u
# Print commands
set -x

if [ "${CI:-}" == 'bootstrap' ]; then
  # Test harness will checkout code to directory $GOPATH/src/github.com/istio/istio
  # but we depend on being at path $GOPATH/src/istio.io/istio for imports
  ln -sf ${GOPATH}/src/github.com/istio ${GOPATH}/src/istio.io
  ROOT=${GOPATH}/src/istio.io/istio
  cd ${GOPATH}/src/istio.io/istio

  # Use the provided pull head sha, from prow.
  GIT_SHA="${PULL_PULL_SHA}"

  # check if rewrite history is present
  PR_BRANCH=$(git show-ref | grep refs/pr | awk '{print $2}')

  if [[ -z $PR_BRANCH ]];then
    echo "Could not get PR branch"
    git show-ref
    exit -1
  fi

  git ls-tree  $PR_BRANCH | grep .history_rewritten_20171102
  if [[ $? -ne 0 ]];then
    echo "This PR is from an out of date clone of istio.io/istio"
    echo "Create a fresh clone of istio.io/istio and re-submit the PR"
    exit -1
  fi

  # Use volume mount from pilot-presubmit job's pod spec.
  # FIXME pilot should not need this
  ln -sf "${HOME}/.kube/config" pilot/platform/kube/config
else
  # Use the current commit.
  GIT_SHA="$(git rev-parse --verify HEAD)"
fi
cd $ROOT

# Build
${ROOT}/bin/init.sh

echo 'Running Unit Tests'
time bazel test --test_output=all //...

# run linters in advisory mode
SKIP_INIT=1 ${ROOT}/bin/linters.sh

HUB="gcr.io/istio-testing"
TAG="${GIT_SHA}"
# upload images
time make push HUB="${HUB}" TAG="${TAG}"
