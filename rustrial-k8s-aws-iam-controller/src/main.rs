#[macro_use]
extern crate log;
use futures::{FutureExt, StreamExt};
use indoc::indoc;
use k8s_openapi::api::core::v1::ServiceAccount;
use kube::{api::ListParams, Api, Client, Config};
use kube_runtime::{reflector, reflector::store::Writer, watcher};
use log::{error, info, warn};
use metrics_exporter_prometheus::PrometheusBuilder;
use rusoto_core::{
    credential::{AutoRefreshingProvider, DefaultCredentialsProvider, ProvideAwsCredentials},
    HttpClient, Region,
};
use rusoto_sts::{GetCallerIdentityRequest, Sts, StsClient, WebIdentityProvider};
use rustrial_k8s_aws_iam_apis::{RoleUsagePolicy, TrustPolicyStatement};
use std::future::pending;

mod arn;
mod gc;
use gc::*;
pub mod iam_policy;
mod service_account_controller;
use service_account_controller::*;

mod trust_policy_statement_controller;
use async_trait::async_trait;
use trust_policy_statement_controller::*;
#[derive(thiserror::Error, Debug)]
enum CrdError {
    #[error("{0}")]
    Any(String),
}

impl From<anyhow::Error> for CrdError {
    fn from(e: anyhow::Error) -> Self {
        CrdError::Any(format!("{}", e))
    }
}

// Data we want access to in error/reconcile calls
#[derive(Clone)]
struct Configuration {
    client: Client,
    trust_policy_statment: Api<TrustPolicyStatement>,
    service_account: Api<ServiceAccount>,
    role_usage_policy: Api<RoleUsagePolicy>,
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[derive(Clone)]
pub struct AwsCredentialsProvider {
    web_identity_provider: WebIdentityProvider,
    default: DefaultCredentialsProvider,
}

impl AwsCredentialsProvider {
    fn new() -> anyhow::Result<Self> {
        Ok(Self {
            web_identity_provider: WebIdentityProvider::from_k8s_env(),
            default: DefaultCredentialsProvider::new()?,
        })
    }
}

#[async_trait]
impl ProvideAwsCredentials for AwsCredentialsProvider {
    async fn credentials(
        &self,
    ) -> Result<rusoto_core::credential::AwsCredentials, rusoto_core::credential::CredentialsError>
    {
        match self.web_identity_provider.credentials().await {
            Err(e) => {
                warn!("failed to obtain AWS credentials from IRSA, will fallback to default credentials provider: {}", e);
                self.default.credentials().await
            }
            c => c,
        }
    }
}

// Helper with verbose error logging.
async fn get_aws_provider() -> anyhow::Result<AutoRefreshingProvider<AwsCredentialsProvider>> {
    let hint = indoc! {r#"
        Controller terminated due to wrong or missing AWS Role setup, please fix controller's
        AWS permission according to the instructions below.

        The controller must run with a valid IAM Role for ServiceAccounts (IRSA), see
        https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
        for more information about IRSA.

        The AWS Role for the controller needs the following permissions:

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

        Make sure that the IAM Role has a Trust Policy which allows your EKS Cluster to assume that role.
        Basically, you will have to add a Trust Policy Statment that lools like this, with all the 
        `${...}` placeholders replaced with your EKS Cluster specific values:

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

        Check the documentation at https://github.com/rustrial/k8s-aws-iam-controller for more information.
    "#};

    let inner = match AwsCredentialsProvider::new() {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to create AwsCredentialsProvider: {}\n\n{}", e, hint);
            Err(e)?
        }
    };
    let provider = match AutoRefreshingProvider::new(inner) {
        Err(e) => {
            error!(
                "Failed to create AutoRefreshingProvider for AWS credentials: {}\n\n{}",
                e, hint
            );
            Err(e)?
        }
        Ok(p) => p,
    };
    match provider.credentials().await {
        Ok(_) => Ok(provider),
        Err(e) => {
            log::error!("Unable to obtain AWS credentials: {}\n\n{}", e, hint);
            Err(e)?
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let provider = get_aws_provider().await?;
    let sts_client = StsClient::new_with(HttpClient::new()?, provider.clone(), Region::default());
    let whoami = sts_client
        .get_caller_identity(GetCallerIdentityRequest::default())
        .await?;

    info!("Controller is running with AWS Identity {:?}", whoami);
    let oidc_provider_arn = env_var("OIDC_PROVIDER_ARN");
    let metrics_builder = PrometheusBuilder::new();
    metrics_builder.install()?;
    let client = Client::try_default().await?;
    let client_config = Config::infer().await?;
    let (service_account, trust_policy_statment) = if let Some(ns) = env_var("WATCH_NAMESPACE") {
        info!("Controller is only watching resources in namespace {}", ns);
        (
            Api::<ServiceAccount>::namespaced(client.clone(), ns.as_str()),
            Api::<TrustPolicyStatement>::namespaced(client.clone(), ns.as_str()),
        )
    } else {
        info!("Controller is watching resources in all namespaces");
        (
            Api::<ServiceAccount>::all(client.clone()),
            Api::<TrustPolicyStatement>::all(client.clone()),
        )
    };
    let storage_namespace =
        env_var("STORAGE_NAMESPACE").unwrap_or_else(|| client_config.default_ns);
    info!(
        "Controller is using {} as storage namesapce for RoleUsagePolicy objects",
        storage_namespace
    );
    // Only consider RoleUsagePolicy object's from the storage namespace.
    let role_usage_policy =
        Api::<RoleUsagePolicy>::namespaced(client.clone(), storage_namespace.as_str());
    // Create RoleUsagePolicy Index (store & reflector)
    let (useage_policy_reflector_loop, useage_policy_store) = {
        let useage_policy_watcher = watcher(role_usage_policy.clone(), ListParams::default());
        let useage_policy_writer = Writer::<RoleUsagePolicy>::default();
        let useage_policy_store = useage_policy_writer.as_reader();
        let useage_policy_reflector = reflector(useage_policy_writer, useage_policy_watcher);
        let useage_policy_reflector_loop = useage_policy_reflector.for_each(|res| async move {
            match res {
                Ok(o) => {
                    info!("RoleUsagePolicy Reflector {:?}", o)
                }
                Err(e) => {
                    warn!("RoleUsagePolicy Refelctor failed: {}", e)
                }
            }
        });
        (useage_policy_reflector_loop, useage_policy_store)
    };
    let configuration = Configuration {
        client: client.clone(),
        trust_policy_statment,
        service_account,
        role_usage_policy,
    };
    let (_service_account_store, service_account_controller) = if let Some(oidc_provider_arn) =
        oidc_provider_arn
    {
        // If OpenID Connect Provider ARN is provided start service account controller.
        let service_account_controller = ServiceAccountController {
            configuration: configuration.clone(),
            oidc_provider_arn,
        };
        let (service_account_store, service_account_controller) =
            service_account_controller.start();
        (
            Some(service_account_store),
            service_account_controller.boxed(),
        )
    } else {
        let hint = indoc! {r#"
            ServiceAccount controller is disabled as OIDC_PROVIDER_ARN environment variable is not set,
            no TrustPolicyStatement objects will be created for your ServiceAccount objects. This is 
            likely not what you want, and you shold pass the EKS Cluster's AWS OpenID Connect Provider
            ARN via environment variable OIDC_PROVIDER_ARN.
            
            Check the documentation at https://github.com/rustrial/k8s-aws-iam-controller for more information.
        "#};
        warn!("{}", hint);
        (None, pending().boxed())
    };

    let tust_policy_statement_controller = TrustPolicyStatementController {
        whoami,
        provider: provider.clone(),
        configuration: configuration.clone(),
        useage_policy_cache: useage_policy_store.clone(),
    };

    let garbage_collector = GarbageCollector { provider };

    let schedule = tokio::spawn(garbage_collector.start());

    tokio::select! {
       _ = service_account_controller => (),
       _ = tust_policy_statement_controller.start() => (),
       _ = useage_policy_reflector_loop => (),
       _ = schedule => (),
    };
    Ok(())
}
