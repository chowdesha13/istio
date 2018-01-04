#!/usr/bin/env bash

if [ ! -f $GOPATH/bin/minikube ]; then
    curl -Lo $GOPATH/bin/minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 && chmod +x minikube
fi
if [ ! -f $GOPATH/bin/kubectl ]; then
    curl -Lo $GOPATH/bin/kubectl https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl && chmod +x kubectl
fi

export MINIKUBE_WANTUPDATENOTIFICATION=false
export MINIKUBE_WANTREPORTERRORPROMPT=false
export MINIKUBE_HOME=$HOME
export CHANGE_MINIKUBE_NONE_USER=true

export KUBECONFIG=${KUBECONFIG:-$GOPATH/minikube.conf}

function waitMinikube() {
    kubectl cluster-info
    set -ne
    # this for loop waits until kubectl can access the api server that Minikube has created
    for i in {1..150}; do # timeout for 5 minutes
       ./kubectl get po &> /dev/null
       if [ $? -ne 1 ]; then
          break
      fi
      sleep 2
    done
    kubectl get svc --all-namespaces
    cat $KUBECONFIG
}


# Requires sudo ! Start real kubernetes minikube with none driver
function startMinikubeNone() {
    sudo -E minikube start \
            --extra-config=apiserver.Admission.PluginNames="Initializers,NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,GenericAdmissionWebhook,ResourceQuota" \
            --kubernetes-version=v1.7.5 --vm-driver=none
    sudo -E minikube update-context
    sudo chown -R $(uid -u) $KUBECONFIG $HOME/.minikube
}

function stopMinikube() {
    sudo minikube stop
}

case "$1" in
    start) startMinikubeNone ;;
    stop) stopMinikube ;;
    wait) waitMinikube ;;
esac