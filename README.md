[![Artifact HUB](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/k8s-aws-iam-controller)](https://artifacthub.io/packages/search?repo=k8s-aws-iam-controller)

# AWS IAM Controller for Kubernetes

[Kubernetes Controller](https://kubernetes.io/docs/concepts/architecture/controller/) to establish
AWS IAM Role [Trust Policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html)
statements for
[IAM Roles for ServiceAccounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html).

## Background & Motivation for this project

[AWS EKS](https://aws.amazon.com/eks) supports
[IAM Roles for ServiceAccounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
to enable Pods to obtain temporary AWS IAM credentials to access AWS services. This is achieved by annotating
ServiceAccount objects with the corresponding AWS IAM Role's ARN:

```yaml
kind: ServiceAccount
apiVersion: v1
metadata:
  name: my-service-account
  namespace: default
  annotations:
    # AWS IAM Role (ARN) associated with this ServiceAccount
    eks.amazonaws.com/role-arn: "arn:aws:iam::000000000000:role/role-name"
```

In order for the Pod to be able assume that AWS IAM Role an EKS **cluster specific**
[Trust Policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html)
statement must be added to the IAM Role.

```json
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::000000000000:oidc-provider/oidc.eks.eu-central-1.amazonaws.com/id/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.eu-central-1.amazonaws.com/id/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:sub": "system:serviceaccount:default:my-service-account"
        }
      }
    }
  ]
}
```

Usually, this is done upfront either manually or using infrastructure management tools like
Pulumi, Terrform or CloudFormation. However, this approach fails if Kubernetes
clusters are not known upfront and can come and go dynamically. Each EKS cluster will have
a unique (unpredictable) OpenID Connect Provider (`oidc-provider`) ARN, which must be added
to the IAM Role's trust policy.

This controller addresses this poblem and dynamically manages the required trust policy
statements for the current Kubernetes cluster. It is implemented by two Kubernetes
(sub)controllers:

- **ServiceAccount Controller** watches for `ServiceAccount` objects that
  contain an `eks.amazonaws.com/role-arn` annotation, and creates
  `TrustPolicyStatement` object for each such `ServiceAccount`.
  `ServiceAccount` objects can opt-out by setting the
  `iam.aws.rustrial.org/trust-policy-statement` annotation (or label) to value "`disable`".
- **TrustPolicyStatement Controller** watches for `TrustPolicyStatement` objects and uses
  `RoleUsagePolicy` objects to verify whether the namespace of the
  `TrustPolicyStatement` is authorized to use (assume) the corresponding IAM Role or not.
  If authorized, it will update the AWS IAM Role's trust policy using the
  [UpdateAssumeRolePolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAssumeRolePolicy.html)
  API endpoint.

## How it works

Note: `ServiceAccount` objects can opt-out by setting the `iam.aws.rustrial.org/trust-policy-statement` annotation (or label) to `disable`.

```yaml
---
# Auhtorize the use of the `arn:aws:iam::000000000000:role/cluster-autoscaler-role` role in
# namespace `kube-system`.
kind: RoleUsagePolicy
metadata:
  name: cluster-autoscaler
  namespace: kube-system
spec:
  roleArn: "arn:aws:iam::000000000000:role/cluster-autoscaler-role"
  namespaces:
    - kube-system
---
kind: ServiceAccount
apiVersion: v1
metadata:
  name: cluster-autoscaler
  namespace: kube-system
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::000000000000:role/cluster-autoscaler-role"
```

For example with the above objects in place, the controller will create an `TrustPolicyStament`
object like this:

```yaml
apiVersion: iam.aws.rustrial.org/v1alpha1
kind: TrustPolicyStatement
metadata:
  finalizers:
    - iam.aws.rustrial.org
  name: cluster-autoscaler
  namespace: kube-system
  ownerReferences:
    - apiVersion: v1
      blockOwnerDeletion: false
      controller: true
      kind: ServiceAccount
      name: cluster-autoscaler
      uid: 109070af-b481-42f2-8dbe-c8f8d1221fea
spec:
  providerArn: >-
    arn:aws:iam::000000000000:oidc-provider/oidc.eks.eu-central-1.amazonaws.com/id/F9C16C0A32FC4A6972962AA8025418C7
  roleArn: "arn:aws:iam::000000000000:role/cluster-autoscaler-role"
  serviceAccountName: cluster-autoscaler
  statementSid: EKSeb7a1df89825c0d695a3f40d5d8749fc04b0011990ea23d758a7ae7f5cee08ddX
status:
  authorizations:
    - kind: RoleUsagePolicy
      name: cluster-autoscaler
      namespace: kube-system
  conditions:
    - lastTransitionTime: "2021-03-02T10:07:13Z"
      message: ""
      observedGeneration: 1
      reason: Success
      status: "True"
      type: Ready
```

## Security Considerations

The controller can be run in _cluster_ or _namespace_ mode, by default it will run in cluster mode.

- In _cluster mode_ the controller will process `ServiceAccount` and `TrustPolicyStatement` objects
  from all namspaces.
- In _namespace mode_ it will only process `ServiceAccount` and `TrustPolicyStatement` objects from
  the namespace specified in the environment variable `WATCH_NAMESPACE`. This can be usefull to run
  the controller in a multi-tenant cluster without cluster-admin rights.

No matter in which mode the controller is running it will only read `RoleUsagePolicy` objects
from the _storage namespace_, which defaults to the namespace the controller is running in.
The _storage namespace_ can be changed by setting the `STORAGE_NAMESPACE` environment variable.
Carefully choose your _storage namespace_ and make sure only authorized entities can create or
modify `RoleUsagePolicy` objects in that namespace.

## Getting Started

Check the [Helm Chart Readme](charts/k8s-aws-iam-controller/README.md) for instructions on
how to install this controller.

## Resource Lifecycle & Garbage Collection

The controller uses [finalizer](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#finalizers) pattern to make sure stale Trust Policy Statements are removed
from AWS IAM Roles. However, there are some edge conditions (e.g. controller is no longer running
or Kubernetes cluster is deleted) which can lead to stale Trust Policy Statements not being removed
from AWS IAM Roles.

As a (best-effort) mitigation measurement, the controller runs a garbage collector which will scan
all IAM Roles in the current AWS account and remove stale _Trust Policy Statements_.
The garbage collector will remove _Trust Policy Statements_ which adhere to the following rules:

- The _Trust Policy Statement_'s `Sid` is not empty.
- Single (non array) principal entry of type `Federated`, which refers to an EKS _OpenID Connect Provider_
  in the same AWS account as the Role and matches the following regular expression
  "`^arn:aws:iam::(\d+):oidc-provider/(oidc\.eks\.[^.]+\.amazonaws\.com/id/.*)$`".
- The referred _OpenID Connect Provider_ does no longer exist.

The _Trust Policy Statements_ gargabe collector is turned-on by default and can be turned-off
by setting the environment variable `DISABLE_TRUST_POLICY_STATEMENT_GC` (any value will do).
By default, garbage collection will run once per hour, the interval can be changed by setting
the environment variable `TRUST_POLICY_STATEMENT_GC_INTERVAL_SECONDS`.

---

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license
  ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- The Unlicense
  ([UNLICENSE](LUNLICENSE) or https://opensource.org/licenses/unlicense)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
triple licensed as above, without any additional terms or conditions. See the
[WAIVER](WAIVER) and [CONTRIBUTING.md](CONTRIBUTING.md) files for more information.
