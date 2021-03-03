# Helm Chart Values

| Parameter                        | Description                                                                    | Default Value                                 | Mandatory |
| -------------------------------- | ------------------------------------------------------------------------------ | --------------------------------------------- | --------- |
| `awsIamRole`                     | ARN of the AWS IAM Role of the controller                                      |                                               | yes       |
| `oidcProviderArn`                | Space separated list of ARNs of the AWS EKS Cluster's OpenID Connect Providers |                                               | no(\*)    |
| `awsRegion`                      | AWS Region                                                                     |                                               | no        |
| `watchNamespace`                 | Namespace to watch for `ServiceAccount` and `TrustPolicyStatement` objects.    | `null` (watch all namespaces)                 | no        |
| `storageNamespace`               | Namespace to watch for `RoleUsagePolicy` objects.                              | `null` (watch controller's current namespace) | no        |
| `logLevel`                       | Log level on of `error`, `info`, `debug` or `trace`                            | `info`                                        | no        |
| `disableTrustPolicyStatementGc`  | Disable Trust Policy Statement garbage collector (GC)                          | `false` (GC is enabled by default)            | no        |
| `trustPolicyStatementGcInterval` | Disable Trust Policy Statement GC intervall in seconds                         | `3600` (once per hour)                        | no        |

(\*) If `oidcProviderArn` is not provided the ServiceAccount-Controller will be turned-off
and only the TrustPolicyStatement-Controller will be active. As a consequence,
no `TrustPolicyStatement` objects will be created for annotated `ServiceAccount` objects.

## Prerequisites

**AWS IAM ROle (Permissions)**

The controller itself must run with a valid
[IAM Role for ServiceAccounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
with the following permissions. Of course, you can adapt the `Resource` or `Condition` value for the
`iam:UpdateAssumeRolePolicy` action according to your needs.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetRole",
        "iam:ListRoles",
        "iam:ListOpenIDConnectProviders",
        "iam:ListRoleTags"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["iam:UpdateAssumeRolePolicy"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}
```

Make sure the IAM Role has a Trust Policy which allows your EKS Cluster to assume that role.
See [IAM Roles for ServiceAccounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
for detailed instructions on how to achieve this. Basically, you will have to add a _Trust Policy
Statment_ that lools like this, with all the `${...}` placeholders replaced with your EKS cluster
specific values:

```json
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/oidc.eks.${AWS_REGION}.amazonaws.com/id/${ID}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.${AWS_REGION}.amazonaws.com/id/${ID}:sub": "system:serviceaccount:${SERVICE_ACCOUNT_NAMESPACE}:${SERVICE_ACCOUNT_NAME}"
        }
      }
    }
  ]
}
```

## Installation

Create an AWS IAM Role with the above permissions and pass the role's ARN to the `helm install` command (see below).

**Add Helm Repository**

The controller can be installed via Helm Chart, which by default will use the prebuilt OCI Images for Linux (`amd64` and `arm64`) from [DockerHub](https://hub.docker.com/r/rustrial/k8s-aws-iam-controller).

```shell
helm repo add k8s-aws-iam-controller https://rustrial.github.io/k8s-aws-iam-controller
```

**Install Helm Chart**

```shell
helm install my-k8s-aws-iam-controller k8s-aws-iam-controller/k8s-aws-iam-controller \
     --version 0.1.0 \
     --set awsIamRole=arn:aws:iam::000000000000:role/k8s-aws-iam-controller \
     --set oidcProviderArn=arn:aws:iam::000000000000:oidc-provider/oidc.eks.eu-central-1.amazonaws.com/id/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
     --set awsRegion=eu-central-1
```
