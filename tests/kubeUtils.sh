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

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. ${TESTS_DIR}/commonUtils.sh || { echo "Cannot load common utilities"; exit 1; }

K8CLI="kubectl"

# Create a kube namespace to isolate test
create_namespace(){
    print_block_echo "Creating kube namespace"
    $K8CLI create namespace $NAMESPACE \
    || error_exit 'Failed to create namespace'
}

# Bring up control plane
deploy_istio() {
    print_block_echo "Deploying ISTIO"
    $K8CLI -n $NAMESPACE create -f "${TESTS_DIR}/istio/controlplane.yaml" \
      || error_exit 'Failed to create control plane'
    for (( i=0; i<=19; i++ ))
    do
        ready=$($K8CLI -n $NAMESPACE get pods | awk 'NR>1 {print $1 "\t" $2}' | grep "istio" | grep "1/1" | wc -l)
        if [ $ready -eq 2 ]
        then
            echo "ISTIO control plane deployed"
            return 0
        fi
        sleep 10
    done
    echo "Unable to deploy ISTIO"
    return 1
}

# Deploy the bookinfo microservices
deploy_bookinfo(){
    print_block_echo "Deploying BookInfo to kube"

    $K8CLI -n $NAMESPACE create -f "${TESTS_DIR}/apps/bookinfo/bookinfo.yaml" \
      || error_exit 'Failed to deploy bookinfo'
    for (( i=0; i<=49; i++ )) # Has to be this high to prevent flaky tests, caused by kube taking an age pulling images
    do
        ready=$($K8CLI -n $NAMESPACE get pods | awk 'NR>1 {print $1 "\t" $2}' | grep -v "istio" | grep "2/2" | wc -l)
        if [ $ready -eq 6 ]
        then
            echo "BookInfo deployed"
            return 0
        fi
        sleep 10
    done
    echo "Unable to deploy BookInfo"
    return 1
}

# Clean up all the things
cleanup(){
    print_block_echo "Cleaning up ISTIO"
    $K8CLI -n $NAMESPACE delete -f "${TESTS_DIR}/istio/controlplane.yaml"
    print_block_echo "Cleaning up BookInfo"
    $K8CLI -n $NAMESPACE delete -f "${TESTS_DIR}/apps/bookinfo/bookinfo.yaml"
    print_block_echo "Deleting namespace"
    $K8CLI delete namespace $NAMESPACE
}

# Debug dump for failures
dump_debug() {
    echo ""
    $K8CLI -n $NAMESPACE get pods
    $K8CLI -n $NAMESPACE get thirdpartyresources
    $K8CLI -n $NAMESPACE get thirdpartyresources -o json
    GATEWAY_PODNAME=$($K8CLI -n $NAMESPACE get pods | grep istio-ingress | awk '{print $1}')
    $K8CLI -n $NAMESPACE logs $GATEWAY_PODNAME
    PRODUCTPAGE_PODNAME=$($K8CLI -n $NAMESPACE get pods | grep productpage | awk '{print $1}')
    $K8CLI -n $NAMESPACE logs $PRODUCTPAGE_PODNAME -c productpage
    $K8CLI -n $NAMESPACE logs $PRODUCTPAGE_PODNAME -c proxy
    $K8CLI -n $NAMESPACE get istioconfig -o yaml
}
