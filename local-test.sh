#!/bin/bash

export KIND=02e1a677-483f-4916-b49e-7b6afbdc72da
export KUBECONFIG=".kube-config"

kind create cluster --name $KIND --kubeconfig $KUBECONFIG

kubectl delete deployment -n kube-system k8s-aws-iam-controller

./.github/install.sh "$@"

./.github/e2e-tests.sh