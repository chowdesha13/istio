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

# This file is temporary compatibility between old update version
# and helm template based generation
set -e
set -o errexit
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
VERSION_FILE="istio.VERSION"
TEMP_DIR="/tmp"
DEST_DIR=$ROOT
COMPONENT_FILES=false

# set the default values
ISTIO_NAMESPACE="istio-system"
FORTIO_HUB="docker.io/istio"
FORTIO_TAG="latest_release"
HYPERKUBE_HUB="quay.io/coreos/hyperkube"
HYPERKUBE_TAG="v1.7.6_coreos.0"

function usage() {
  [[ -n "${1}" ]] && echo "${1}"

  cat <<EOF
usage: ${BASH_SOURCE[0]} [options ...]"
  options:
    -i ... URL to download istioctl binary
    -p ... <hub>,<tag> for the pilot docker image
    -x ... <hub>,<tag> for the mixer docker image
    -c ... <hub>,<tag> for the citadel docker image
    -a ... <hub>,<tag> Specifies same hub and tag for pilot, mixer, proxy, and citadel containers
    -h ... <hub>,<tag> for the hyperkube docker image
    -o ... <hub>,<tag> for the proxy docker image
    -n ... <namespace> namespace in which to install Istio control plane components
    -A ... URL to download auth debian packages
    -P ... URL to download pilot debian packages
    -E ... URL to download proxy debian packages
    -d ... directory to store file (optional, defaults to source code tree)
    -D ... enable debug for proxy (optional, false or true, default is false)
    -m ... true|false Create the individual component files as well as the all-in-one
EOF
  exit 2
}

while getopts :n:p:x:c:a:h:o:P:d:D:m: arg; do
  case ${arg} in
    n) ISTIO_NAMESPACE="${OPTARG}";;
    p) PILOT_HUB_TAG="${OPTARG}";;     # Format: "<hub>,<tag>"
    x) MIXER_HUB_TAG="${OPTARG}";;     # Format: "<hub>,<tag>"
    c) CITADEL_HUB_TAG="${OPTARG}";;   # Format: "<hub>,<tag>"
    a) ALL_HUB_TAG="${OPTARG}";;       # Format: "<hub>,<tag>"
    h) HYPERKUBE_HUB_TAG="${OPTARG}";; # Format: "<hub>,<tag>"
    o) PROXY_HUB_TAG="${OPTARG}";;     # Format: "<hub>,<tag>"
    P) PILOT_DEBIAN_URL="${OPTARG}";;
    d) DEST_DIR="${OPTARG}";;
    D) PROXY_DEBUG="${OPTARG}";;
    m) COMPONENT_FILES=true;;
    *) usage;;
  esac
done

if [[ -n ${ALL_HUB_TAG} ]]; then
    PILOT_HUB="$(echo ${ALL_HUB_TAG}|cut -f1 -d,)"
    PILOT_TAG="$(echo ${ALL_HUB_TAG}|cut -f2 -d,)"
    PROXY_HUB="$(echo ${ALL_HUB_TAG}|cut -f1 -d,)"
    PROXY_TAG="$(echo ${ALL_HUB_TAG}|cut -f2 -d,)"
    MIXER_HUB="$(echo ${ALL_HUB_TAG}|cut -f1 -d,)"
    MIXER_TAG="$(echo ${ALL_HUB_TAG}|cut -f2 -d,)"
    CITADEL_HUB="$(echo ${ALL_HUB_TAG}|cut -f1 -d,)"
    CITADEL_TAG="$(echo ${ALL_HUB_TAG}|cut -f2 -d,)"
fi

if [[ -n ${PROXY_HUB_TAG} ]]; then
    PROXY_HUB="$(echo ${PROXY_HUB_TAG}|cut -f1 -d,)"
    PROXY_TAG="$(echo ${PROXY_HUB_TAG}|cut -f2 -d,)"
fi

if [[ -n ${PILOT_HUB_TAG} ]]; then
    PILOT_HUB="$(echo ${PILOT_HUB_TAG}|cut -f1 -d,)"
    PILOT_TAG="$(echo ${PILOT_HUB_TAG}|cut -f2 -d,)"
fi

if [[ -n ${MIXER_HUB_TAG} ]]; then
    MIXER_HUB="$(echo ${MIXER_HUB_TAG}|cut -f1 -d,)"
    MIXER_TAG="$(echo ${MIXER_HUB_TAG}|cut -f2 -d,)"
fi

if [[ -n ${CITADEL_HUB_TAG} ]]; then
    CITADEL_HUB="$(echo ${CITADEL_HUB_TAG}|cut -f1 -d,)"
    CITADEL_TAG="$(echo ${CITADEL_HUB_TAG}|cut -f2 -d,)"
fi

if [[ -n ${HYPERKUBE_HUB_TAG} ]]; then
    HYPERKUBE_HUB="$(echo ${HYPERKUBE_HUB_TAG}|cut -f1 -d,)"
    HYPERKUBE_TAG="$(echo ${HYPERKUBE_HUB_TAG}|cut -f2 -d,)"
fi


function error_exit() {
  # ${BASH_SOURCE[1]} is the file name of the caller.
  echo "${BASH_SOURCE[1]}: line ${BASH_LINENO[0]}: ${1:-Unknown Error.} (exit ${2:-1})" 1>&2
  exit ${2:-1}
}

#
# In-place portable sed operation
# the sed -i operation is not defined by POSIX and hence is not portable
#
function execute_sed() {
  sed -e "${1}" $2 > $2.new
  mv -- $2.new $2
}

function update_version_file() {
  cat <<EOF > "${DEST_DIR}/${VERSION_FILE}"
# DO NOT EDIT THIS FILE MANUALLY instead use
# install/updateVersion.sh (see install/README.md)
export CITADEL_HUB="${CITADEL_HUB}"
export CITADEL_TAG="${CITADEL_TAG}"
export MIXER_HUB="${MIXER_HUB}"
export MIXER_TAG="${MIXER_TAG}"
export PILOT_HUB="${PILOT_HUB}"
export PILOT_TAG="${PILOT_TAG}"
export PROXY_HUB="${PROXY_HUB}"
export PROXY_TAG="${PROXY_TAG}"
export PROXY_DEBUG="${PROXY_DEBUG}"
export ISTIO_NAMESPACE="${ISTIO_NAMESPACE}"
export PILOT_DEBIAN_URL="${PILOT_DEBIAN_URL}"
export FORTIO_HUB="${FORTIO_HUB}"
export FORTIO_TAG="${FORTIO_TAG}"
export HYPERKUBE_HUB="${HYPERKUBE_HUB}"
export HYPERKUBE_TAG="${HYPERKUBE_TAG}"
EOF
}

function update_istio_addons() {
  SRC_DIR=$ROOT/install/kubernetes/addons
  DEST=$DEST_DIR/install/kubernetes/addons
  mkdir -p $DEST
  sed "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|" $SRC_DIR/zipkin.yaml.tmpl > $DEST/zipkin.yaml
}

function gen_file() {
    fl=$1
    dest=$2
    make $1   # make always places the files in install/...
    # If the two paths are not to the same file.
    if [[ ! install/kubernetes/$fl -ef ${dest}/install/kubernetes/$fl ]]; then
      # Potentially overwrites the file generated by updateVersion_orig.sh.
      cp -f install/kubernetes/$fl ${dest}/install/kubernetes/$fl
    fi
}

function gen_istio_files() {
    if [[ ! -z ${ISTIO_RELEASE:-} ]]; then
        for target in istio-demo.yaml istio-demo-auth.yaml; do
            gen_file $target ${DEST_DIR}
        done
    else
        for target in istio.yaml istio-auth.yaml istio-one-namespace.yaml istio-one-namespace-auth.yaml istio-multicluster.yaml istio-auth-multicluster.yaml istio-remote.yaml istio-galley.yaml istio-auth-galley.yaml;do
            gen_file $target ${DEST_DIR}
        done
    fi
}

function update_istio_install_docker() {
  pushd $TEMP_DIR/templates
  execute_sed "s|image: {PILOT_HUB}/\(.*\):{PILOT_TAG}|image: ${PILOT_HUB}/\1:${PILOT_TAG}|" istio.yaml.tmpl
  execute_sed "s|image: {PROXY_HUB}/\(.*\):{PROXY_TAG}|image: ${PROXY_HUB}/\1:${PROXY_TAG}|" bookinfo.sidecars.yaml.tmpl
  popd
}

# Generated merge yaml files for easy installation
function merge_files_docker() {
  TYPE=$1
  SRC=$TEMP_DIR/templates

  # Merge istio.yaml install file
  INSTALL_DEST=$DEST_DIR/install/$TYPE
  ISTIO=${INSTALL_DEST}/istio.yaml

  mkdir -p $INSTALL_DEST
  echo "# GENERATED FILE. Use with Docker-Compose and ${TYPE}" > $ISTIO
  echo "# TO UPDATE, modify files in install/${TYPE}/templates and run install/updateVersion.sh" >> $ISTIO
  cat $SRC/istio.yaml.tmpl >> $ISTIO

  # Merge bookinfo.sidecars.yaml sample file
  SAMPLES_DEST=$DEST_DIR/samples/bookinfo/platform/$TYPE
  BOOKINFO=${SAMPLES_DEST}/bookinfo.sidecars.yaml

  mkdir -p $SAMPLES_DEST
  echo "# GENERATED FILE. Use with Docker-Compose and ${TYPE}" > $BOOKINFO
  echo "# TO UPDATE, modify files in samples/bookinfo/platform/${TYPE}/templates and run install/updateVersion.sh" >> $BOOKINFO
  cat $SRC/bookinfo.sidecars.yaml.tmpl >> $BOOKINFO
}

function gen_platforms_files() {
    for platform in consul
    do
        cp -R $ROOT/install/$platform/templates $TEMP_DIR/templates
        cp -a $ROOT/samples/bookinfo/platform/$platform/templates/. $TEMP_DIR/templates/
        update_istio_install_docker
        merge_files_docker $platform
        rm -R $TEMP_DIR/templates
    done
}

function gen_citadel_extra_files() {
    SRC_DIR=$ROOT/install/kubernetes/citadel_extras
    DEST=$DEST_DIR/install/kubernetes
    sed -e "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|;s|image: {CITADEL_HUB}/\(.*\):{CITADEL_TAG}|image: ${CITADEL_HUB}/\1:${CITADEL_TAG}|" \
    $SRC_DIR/istio-citadel-plugin-certs.yaml.tmpl > $DEST/istio-citadel-plugin-certs.yaml
    sed -e "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|;s|image: {CITADEL_HUB}/\(.*\):{CITADEL_TAG}|image: ${CITADEL_HUB}/\1:${CITADEL_TAG}|" \
    $SRC_DIR/istio-citadel-with-health-check.yaml.tmpl > $DEST/istio-citadel-with-health-check.yaml
    sed -e "s|{ISTIO_NAMESPACE}|${ISTIO_NAMESPACE}|;s|image: {CITADEL_HUB}/\(.*\):{CITADEL_TAG}|image: ${CITADEL_HUB}/\1:${CITADEL_TAG}|" \
    $SRC_DIR/istio-citadel-standalone.yaml.tmpl > $DEST/istio-citadel-standalone.yaml
}

#
# Script work begins here
#

# Create the destination dir if necessary
if [[ "$DEST_DIR" != "$ROOT" ]]; then
  if [ ! -d "$DEST_DIR" ]; then
    mkdir -p $DEST_DIR
  fi
  cp -R $ROOT/install $DEST_DIR/
  cp -R $ROOT/samples $DEST_DIR/
fi

# Set the HUB and TAG to be picked by the Helm template
if [[ ! -z ${ALL_HUB_TAG} ]]; then
    export HUB="$(echo ${ALL_HUB_TAG}|cut -f1 -d,)"
    export TAG="$(echo ${ALL_HUB_TAG}|cut -f2 -d,)"
fi

# Update the istio.VERSION file
update_version_file

# Generate the addons which aren't covered by Helm charts (zipkin)
update_istio_addons

# Generate the istio*.yaml files
gen_istio_files

# Generate platform files (consul)
gen_platforms_files

# Generate extra Citadel files from their templates
gen_citadel_extra_files
