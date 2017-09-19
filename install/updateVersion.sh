#!/bin/bash

# Copyright 2017 Istio Authors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at

#       http://www.apache.org/licenses/LICENSE-2.0

#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
VERSION_FILE="${ROOT}/istio.VERSION"
TEMP_DIR="/tmp"
GIT_COMMIT=false
CHECK_GIT_STATUS=false

set -o errexit
set -o pipefail
set -x

function usage() {
  [[ -n "${1}" ]] && echo "${1}"

  cat <<EOF
usage: ${BASH_SOURCE[0]} [options ...]"
  options:
    -i ... URL to download istioctl binary
    -p ... <hub>,<tag> for the pilot docker image
    -x ... <hub>,<tag> for the mixer docker image
    -c ... <hub>,<tag> for the istio-ca docker image
    -g ... create a git commit for the changes
    -n ... <namespace> namespace in which to install Istio control plane components
    -s ... check if template files have been updated with this tool
    -A ... URL to download auth debian packages
    -P ... URL to download pilot debian packages
    -E ... URL to download proxy debian packages
EOF
  exit 2
}

source "$VERSION_FILE" || error_exit "Could not source versions"

while getopts :gi:n:p:x:c:sA:P:E: arg; do
  case ${arg} in
    i) ISTIOCTL_URL="${OPTARG}";;
    n) ISTIO_NAMESPACE="${OPTARG}";;
    p) PILOT_HUB_TAG="${OPTARG}";; # Format: "<hub>,<tag>"
    x) MIXER_HUB_TAG="${OPTARG}";; # Format: "<hub>,<tag>"
    c) CA_HUB_TAG="${OPTARG}";; # Format: "<hub>,<tag>"
    g) GIT_COMMIT=true;;
    s) CHECK_GIT_STATUS=true;;
    A) AUTH_DEBIAN_URL="${OPTARG}";;
    P) PILOT_DEBIAN_URL="${OPTARG}";;
    E) PROXY_DEBIAN_URL="${OPTARG}";;
    *) usage;;
  esac
done

if [[ -n ${PILOT_HUB_TAG} ]]; then
    PILOT_HUB="$(echo ${PILOT_HUB_TAG}|cut -f1 -d,)"
    PILOT_TAG="$(echo ${PILOT_HUB_TAG}|cut -f2 -d,)"
fi

if [[ -n ${MIXER_HUB_TAG} ]]; then
    MIXER_HUB="$(echo ${MIXER_HUB_TAG}|cut -f1 -d,)"
    MIXER_TAG="$(echo ${MIXER_HUB_TAG}|cut -f2 -d,)"
fi

if [[ -n ${CA_HUB_TAG} ]]; then
    CA_HUB="$(echo ${CA_HUB_TAG}|cut -f1 -d,)"
    CA_TAG="$(echo ${CA_HUB_TAG}|cut -f2 -d,)"
fi

function error_exit() {
  # ${BASH_SOURCE[1]} is the file name of the caller.
  echo "${BASH_SOURCE[1]}: line ${BASH_LINENO[0]}: ${1:-Unknown Error.} (exit ${2:-1})" 1>&2
  exit ${2:-1}
}

function set_git() {
  if [[ ! -e "${HOME}/.gitconfig" ]]; then
    cat > "${HOME}/.gitconfig" << EOF
[user]
  name = istio-testing
  email = istio.testing@gmail.com
EOF
  fi
}


function create_commit() {
  set_git
  # If nothing to commit skip
  check_git_status && return

  echo 'Creating a commit'
  git commit -a -m "Updating istio version" \
    || error_exit 'Could not create a commit'

}

function check_git_status() {
  local git_files="$(git status -s)"
  [[ -z "${git_files}" ]] && return 0
  return 1
}

# Generated merge yaml files for easy installation
function merge_files() {
  SRC=$TEMP_DIR/templates
  DEST=$ROOT/install/kubernetes

  # istio.yaml file contains a cluster-wide installation
  ISTIO=$DEST/istio.yaml
  ISTIO_ONE_NAMESPACE=$DEST/istio-one-namespace.yaml
  ISTIO_INITIALIZER=$DEST/istio-initializer.yaml
  CONFIG_ENCRYPT=$DEST/istio-config.yaml
  CONFIG_NO_ENCRYPT=$DEST/istio-config-no-encryption.yaml

  # TODO remove 3 lines below once the e2e tests no longer look for this file
  echo "# GENERATED FILE. Use with Kubernetes 1.7+" > $DEST/istio-rbac-beta.yaml
  echo "# TO UPDATE, modify files in install/kubernetes/templates and run install/updateVersion.sh" >> $DEST/istio-rbac-beta.yaml
  cat $SRC/istio-rbac-beta.yaml.tmpl >> $DEST/istio-rbac-beta.yaml

  echo "# GENERATED FILE. Use with Kubernetes 1.7+" > $CONFIG_ENCRYPT
  echo "# TO UPDATE, modify files in install/kubernetes/templates and run install/updateVersion.sh"  >> $CONFIG_ENCRYPT
  cat $SRC/istio-config.yaml.tmpl >> $CONFIG_ENCRYPT

  cp $CONFIG_ENCRYPT $CONFIG_NO_ENCRYPT
  sed -i=.bak "s/authPolicy: MUTUAL_TLS/authPolicy: NONE/" $CONFIG_NO_ENCRYPT

  echo "# GENERATED FILE. Use with Kubernetes 1.7+" > $ISTIO
  echo "# TO UPDATE, modify files in install/kubernetes/templates and run install/updateVersion.sh" >> $ISTIO
  cat $SRC/istio-ns.yaml.tmpl >> $ISTIO
  cat $SRC/istio-rbac-beta.yaml.tmpl >> $ISTIO
  cat $SRC/istio-mixer.yaml.tmpl >> $ISTIO
  cat $SRC/istio-pilot.yaml.tmpl >> $ISTIO
  cat $SRC/istio-ingress.yaml.tmpl >> $ISTIO
  cat $SRC/istio-egress.yaml.tmpl >> $ISTIO


  cp $ISTIO $ISTIO_ONE_NAMESPACE
  # restrict pilot controllers to a single namespace in the test file
  sed -i=.bak "s|args: \[\"discovery\", \"-v\", \"2\"|args: \[\"discovery\", \"-v\", \"2\", \"-a\", \"${ISTIO_NAMESPACE}\"|" $ISTIO_ONE_NAMESPACE
  # TODO the CA templates can be combined
  cat $SRC/istio-ca.yaml.tmpl >> $ISTIO

  cat $SRC/istio-ca-one-namespace.yaml.tmpl >> $ISTIO_ONE_NAMESPACE

  cp ${SRC}/istio-initializer.yaml.tmpl $ISTIO_INITIALIZER
}

function update_version_file() {
  cat <<EOF > "${VERSION_FILE}"
# DO NOT EDIT THIS FILE MANUALLY instead use
# install/updateVersion.sh (see install/README.md)
export CA_HUB="${CA_HUB}"
export CA_TAG="${CA_TAG}"
export MIXER_HUB="${MIXER_HUB}"
export MIXER_TAG="${MIXER_TAG}"
export ISTIOCTL_URL="${ISTIOCTL_URL}"
export PILOT_HUB="${PILOT_HUB}"
export PILOT_TAG="${PILOT_TAG}"
export ISTIO_NAMESPACE="${ISTIO_NAMESPACE}"
export AUTH_DEBIAN_URL="${AUTH_DEBIAN_URL}"
export PILOT_DEBIAN_URL="${PILOT_DEBIAN_URL}"
export PROXY_DEBIAN_URL="${PROXY_DEBIAN_URL}"

EOF
}

function update_istio_install() {
  pushd $TEMP_DIR/templates
  sed -i=.bak "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" istio-config.yaml.tmpl
  sed -i=.bak "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" istio-rbac-beta.yaml.tmpl
  sed -i=.bak "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" istio-pilot.yaml.tmpl
  sed -i=.bak "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" istio-ingress.yaml.tmpl
  sed -i=.bak "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" istio-egress.yaml.tmpl
  sed -i=.bak "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" istio-mixer.yaml.tmpl
  sed -i=.bak "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" istio-ca.yaml.tmpl
  sed -i=.bak "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" istio-ca-one-namespace.yaml.tmpl
  sed -i=.bak "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" istio-initializer.yaml.tmpl

  sed -i=.bak "s|image: {PILOT_HUB}/\(.*\):{PILOT_TAG}|image: ${PILOT_HUB}/\1:${PILOT_TAG}|" istio-pilot.yaml.tmpl
  sed -i=.bak "s|image: {MIXER_HUB}/\(.*\):{MIXER_TAG}|image: ${MIXER_HUB}/\1:${MIXER_TAG}|" istio-mixer.yaml.tmpl
  sed -i=.bak "s|image: {CA_HUB}/\(.*\):{CA_TAG}|image: ${CA_HUB}/\1:${CA_TAG}|" istio-ca.yaml.tmpl
  sed -i=.bak "s|image: {CA_HUB}/\(.*\):{CA_TAG}|image: ${CA_HUB}/\1:${CA_TAG}|" istio-ca-one-namespace.yaml.tmpl

  sed -i=.bak "s|{PILOT_HUB}|${PILOT_HUB}|" istio-initializer.yaml.tmpl
  sed -i=.bak "s|{PILOT_TAG}|${PILOT_TAG}|" istio-initializer.yaml.tmpl

  sed -i=.bak "s|image: {PROXY_HUB}/\(.*\):{PROXY_TAG}|image: ${PILOT_HUB}/\1:${PILOT_TAG}|" istio-ingress.yaml.tmpl
  sed -i=.bak "s|image: {PROXY_HUB}/\(.*\):{PROXY_TAG}|image: ${PILOT_HUB}/\1:${PILOT_TAG}|" istio-egress.yaml.tmpl

  popd
}

function update_istio_addons() {
  DEST=$ROOT/install/kubernetes/addons
  pushd $TEMP_DIR/templates/addons
  sed -i=.bak "s|image: .*/\(.*\):.*|image: ${MIXER_HUB}/\1:${MIXER_TAG}|" grafana.yaml.tmpl
  sed "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" grafana.yaml.tmpl  > $DEST/grafana.yaml
  sed "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" prometheus.yaml.tmpl > $DEST/prometheus.yaml
  sed "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" servicegraph.yaml.tmpl > $DEST/servicegraph.yaml
  sed "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" zipkin.yaml.tmpl > $DEST/zipkin.yaml
  sed "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" zipkin-to-stackdriver.yaml.tmpl > $DEST/zipkin-to-stackdriver.yaml
  popd
}

if [[ ${GIT_COMMIT} == true ]]; then
    check_git_status \
      || error_exit "You have modified files. Please commit or reset your workspace."
fi

cp -R $ROOT/install/kubernetes/templates $TEMP_DIR/templates
update_version_file
update_istio_install
update_istio_addons
merge_files
rm -R $TEMP_DIR/templates

if [[ ${GIT_COMMIT} == true ]]; then
    create_commit
fi

if [[ ${CHECK_GIT_STATUS} == true ]]; then
  check_git_status \
    || { echo "Need to update template and run install/updateVersion.sh"; git diff; exit 1; }
fi
