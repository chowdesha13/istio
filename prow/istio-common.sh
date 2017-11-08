#!/bin/bash

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "*** Calling ${BASH_SOURCE[0]} directly has no effect. It should be sourced."
  exit 0
fi

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
  cd ${ROOT}

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
