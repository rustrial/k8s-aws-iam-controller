#!/bin/bash

set -e

IMG=test/rustrial-k8s-aws-iam-controller:latest

docker image build -t test/rustrial-k8s-aws-iam-controller:latest .

kind load docker-image test/rustrial-k8s-aws-iam-controller:latest --name "${KIND:-kind}"

helm upgrade k8s-aws-iam-controller charts/k8s-aws-iam-controller \
    --install -n kube-system \
    --create-namespace \
    --set fullnameOverride=k8s-aws-iam-controller \
    --set image.repository=test/rustrial-k8s-aws-iam-controller \
    --set image.tag=latest

# helm upgrade k8s-aws-iam-controller charts/k8s-aws-iam-controller \
#     --install -n default \
#     --create-namespace \
#     --set fullnameOverride=k8s-aws-iam-controller \
#     --set image.repository=test/rustrial-k8s-aws-iam-controller \
#     --set image.tag=latest
#     --set watchNamespace=default
#     --set storageNamespace=default