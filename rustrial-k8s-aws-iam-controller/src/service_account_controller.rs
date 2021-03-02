use crate::{Configuration, CrdError};
use anyhow::Context;
use futures::{Future, StreamExt};
use k8s_openapi::{
    api::core::v1::ServiceAccount,
    apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference},
};
use kube::{
    api::{DeleteParams, ListParams, Meta, Patch, PatchParams},
    Api, Error,
};
use kube_runtime::{
    controller::{Context as Ctx, Controller, ReconcilerAction},
    reflector::Store,
};
use log::info;
use metrics::{counter, histogram};
use rustrial_k8s_aws_iam_apis::{
    TrustPolicyStatement, TrustPolicyStatementSpec, API_VERSION, TRUST_POLICY_STATEMENT_LABEL,
};
use sha2::Digest;
use std::time::Instant;
use tokio::time::Duration;

const ROLE_ANNOTATION: &'static str = "eks.amazonaws.com/role-arn";

/// Controller which creates `TrustPolicyStatement` objects from `ServiceAccount` objects
/// that are annotated with an AWS IAM Role.
pub(crate) struct ServiceAccountController {
    pub configuration: Configuration,
    pub oidc_provider_arn: String,
}

impl ServiceAccountController {
    pub fn get_iam_role(sa: &ServiceAccount) -> Option<String> {
        if let Some(a) = &sa.metadata.annotations {
            a.get(ROLE_ANNOTATION)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        } else {
            None
        }
    }

    async fn reconcile_annotated_sa(
        &self,
        sa: &ServiceAccount,
        role_arn: &str,
    ) -> anyhow::Result<ReconcilerAction> {
        let tp = self.get_trust_policy_statement(sa, role_arn).await?;
        let api = if let Some(ns) = tp.namespace() {
            Api::<TrustPolicyStatement>::namespaced(self.configuration.client.clone(), ns.as_str())
        } else {
            Api::<TrustPolicyStatement>::all(self.configuration.client.clone())
        };
        let object =
            serde_json::to_value(&tp).context("Error while serializing TrustPolicyStatement")?;
        api.patch(
            tp.name().as_str(),
            &PatchParams {
                field_manager: Some("iam.aws.rustrial.org".to_string()),
                dry_run: false,
                force: true,
            },
            &Patch::Apply(&object),
        )
        .await?;
        Ok(ReconcilerAction {
            requeue_after: Some(Duration::from_secs(300)),
        })
    }

    async fn get_trust_policy_statement(
        &self,
        sa: &ServiceAccount,
        role_arn: &str,
    ) -> anyhow::Result<TrustPolicyStatement> {
        let api = if let Some(ns) = sa.namespace() {
            Api::<TrustPolicyStatement>::namespaced(self.configuration.client.clone(), ns.as_str())
        } else {
            Api::<TrustPolicyStatement>::all(self.configuration.client.clone())
        };

        // Generate unique, deterministic SID by hashing provider, namespace and name.
        let mut digester = sha2::Sha256::new();
        digester.update(self.oidc_provider_arn.as_bytes());
        digester.update(b":");
        digester.update(sa.namespace().as_deref().unwrap_or("").as_bytes());
        digester.update(b":");
        digester.update(sa.name().as_bytes());
        let digest = digester.finalize();
        // Make sure SID starts and ends with non-numeric characters.
        let statement_sid = format!("EKS{:x}X", digest);

        let spec = TrustPolicyStatementSpec {
            service_account_name: sa.name(),
            role_arn: role_arn.to_string(),
            provider_arn: self.oidc_provider_arn.clone(),
            statement_sid,
        };
        let tp: anyhow::Result<TrustPolicyStatement> = match api.get(sa.name().as_str()).await {
            Err(Error::Api(e)) if e.code == 404 || e.code == 409 => Ok(TrustPolicyStatement {
                api_version: API_VERSION.to_string(),
                kind: "TrustPolicyStatement".to_string(),
                metadata: ObjectMeta {
                    name: Some(sa.name()),
                    namespace: sa.namespace(),
                    ..Default::default()
                },
                spec: spec.clone(),
                status: None,
            }),
            e => Ok(e?),
        };
        let mut tp = tp?;
        tp.metadata.managed_fields = None;
        tp.metadata.owner_references = Some(vec![OwnerReference {
            api_version: "v1".to_string(),
            block_owner_deletion: Some(false),
            controller: Some(true),
            kind: "ServiceAccount".to_string(),
            name: sa.name(),
            uid: sa.metadata.uid.clone().unwrap_or("".to_string()),
        }]);
        tp.spec = spec;
        Ok(tp)
    }

    async fn cleanup(&self, sa: &ServiceAccount) -> anyhow::Result<ReconcilerAction> {
        debug!(
            "cleanup ServiceAccount {}/{}",
            sa.namespace().as_deref().unwrap_or(""),
            sa.name(),
        );
        let api = if let Some(ns) = sa.namespace() {
            Api::<TrustPolicyStatement>::namespaced(self.configuration.client.clone(), ns.as_str())
        } else {
            Api::<TrustPolicyStatement>::all(self.configuration.client.clone())
        };
        let action = ReconcilerAction {
            requeue_after: Some(Duration::from_secs(300)),
        };
        let response = api
            .delete(sa.name().as_str(), &DeleteParams::default())
            .await;
        trace!(
            "delete TrustPolicyStatement {}/{} -> {:?}",
            sa.namespace().as_deref().unwrap_or(""),
            sa.name(),
            response
        );
        match response {
            Ok(_) => Ok(action),
            Err(Error::Api(e)) if e.code == 404 || e.code == 409 => Ok(action),
            Err(e) => Err(e)?,
        }
    }

    fn get_label<'a>(object: &'a ObjectMeta, name: &str) -> Option<&'a str> {
        object
            .labels
            .as_ref()
            .map(|v| v.get(name).map(|v| v.as_ref()))
            .flatten()
    }

    fn get_annotation<'a>(object: &'a ObjectMeta, name: &str) -> Option<&'a str> {
        object
            .annotations
            .as_ref()
            .map(|v| v.get(name).map(|v| v.as_ref()))
            .flatten()
    }

    fn has_label_or_annotation<'a>(
        object: &'a ObjectMeta,
        name: &str,
        values: Vec<&'static str>,
    ) -> bool {
        Self::get_label(object, name)
            .filter(|v| values.iter().filter(|x| *x == v).count() > 0)
            .is_some()
            || Self::get_annotation(object, name)
                .filter(|v| values.iter().filter(|x| *x == v).count() > 0)
                .is_some()
    }

    /// Controller triggers this whenever our main object or our children changed
    async fn reconcile(sa: ServiceAccount, ctx: Ctx<Self>) -> Result<ReconcilerAction, CrdError> {
        let start = Instant::now();
        // ServiceAccounts can opt-out from this controller.
        let opted_out = Self::has_label_or_annotation(
            &sa.metadata,
            TRUST_POLICY_STATEMENT_LABEL,
            vec!["disable", "disabled"],
        );
        // so only process them if they have not opted out:
        let result = if !opted_out {
            if sa.metadata.deletion_timestamp.is_some() {
                // If ServiceAccount has been deleted, delete its TrustPolicyStatement
                ctx.get_ref()
                    .cleanup(&sa)
                    .await
                    .map_err(|e| CrdError::from(e))
            } else if let Some(role_arn) = Self::get_iam_role(&sa) {
                // If a ServiceAccount has a AWS IAM Role annotation, make sure it has a TrustPolicyStatement.
                debug!(
                    "reconile ServiceAccount {}/{} with AWS IAM Role ARN {}",
                    sa.namespace().as_deref().unwrap_or(""),
                    sa.name(),
                    role_arn
                );
                ctx.get_ref()
                    .reconcile_annotated_sa(&sa, role_arn.as_str())
                    .await
                    .map_err(|e| CrdError::from(e))
            } else {
                // If ServiceAccount has no AWS IAM Role annotation, delete its TrustPolicyStatement
                ctx.get_ref()
                    .cleanup(&sa)
                    .await
                    .map_err(|e| CrdError::from(e))
            }
        } else {
            Ok(ReconcilerAction {
                requeue_after: Some(Duration::from_secs(300)),
            })
        };

        let duration = Instant::now() - start;
        histogram!(
            "reconcile_aws_iam_serviceaccount_duration_ns",
            duration.as_nanos() as f64
        );
        result
    }

    /// The controller triggers this on reconcile errors
    fn error_policy(_error: &CrdError, _ctx: Ctx<Self>) -> ReconcilerAction {
        ReconcilerAction {
            requeue_after: Some(Duration::from_secs(10)),
        }
    }

    pub fn start(self) -> (Store<ServiceAccount>, impl Future<Output = ()>) {
        let controller = Controller::new(
            self.configuration.service_account.clone(),
            ListParams::default(),
        );
        let store = controller.store();
        let service_account_controller = controller
            .owns(
                self.configuration.trust_policy_statment.clone(),
                ListParams::default(),
            )
            .run(Self::reconcile, Self::error_policy, Ctx::new(self))
            .for_each(|res| async move {
                match res {
                    Ok(o) => {
                        counter!("reconcile_aws_iam_serviceaccount_success", 1);
                        info!("reconciled {:?}", o)
                    }
                    Err(e) => {
                        counter!("reconcile_aws_iam_serviceaccount_failure", 1);
                        warn!("reconcile failed: {}", e)
                    }
                }
            });
        (store, service_account_controller)
    }
}
