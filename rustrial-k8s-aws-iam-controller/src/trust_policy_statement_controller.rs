use crate::{
    arn::ARN,
    iam_policy::{Action, ConditionMap, Conditions, Effect, PolicyDocument, Principal, Statement},
    AwsCredentialsProvider, Configuration, CrdError,
};
use futures::{Future, StreamExt};
use json_patch::diff;
use kube::{
    api::{ListParams, Meta, Patch, PatchParams},
    Api, Client, Error,
};
use kube_runtime::{
    controller::{Context as Ctx, Controller, ReconcilerAction},
    reflector::{ObjectRef, Store},
};
use lazy_static::lazy_static;
use log::{error, info, warn};
use metrics::{counter, histogram};
use regex::Regex;
use rusoto_core::{
    credential::{AutoRefreshingProvider, ProvideAwsCredentials},
    HttpClient, Region, RusotoError,
};
use rusoto_iam::{
    GetRoleError, GetRoleRequest, Iam, IamClient, ListRoleTagsRequest, Role,
    UpdateAssumeRolePolicyRequest,
};
use rusoto_sts::GetCallerIdentityResponse;
use rustrial_k8s_aws_iam_apis::{
    Authorization, Condition, Provider, RoleUsagePolicy, RoleUsagePolicySpec, TrustPolicyStatement,
    API_GROUP,
};
use std::{collections::HashMap, convert::TryFrom, ops::DerefMut, time::Instant};
use tokio::time::Duration;

const FINALIZER: &'static str = API_GROUP;

const EMPTY_ASSUME_ROLE_POLICY: &'static str = r#"{"Version": "2008-10-17","Statement": []}"#;

lazy_static! {
    pub(crate) static ref ROLE_ARN: Regex =
        Regex::new(r#"^arn:aws:iam::(\d+):role/((?:[^/]+/)*([^/]+))$"#).unwrap();
}

struct IamRoleRef {
    //accountId: String,
    //path_and_name: String,
    name: String,
    arn: String,
}

impl TryFrom<&str> for IamRoleRef {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> anyhow::Result<Self> {
        if let Some(captures) = ROLE_ARN.captures(value) {
            Ok(Self {
                //accountId: captures[1].to_string(),
                //path_and_name: captures[2].to_string(),
                name: captures[3].to_string(),
                arn: value.to_string(),
            })
        } else {
            Err(anyhow::format_err!("Invalid AWS IAM Role ARN: {}", value))
        }
    }
}

impl IamRoleRef {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn resolve(
        &self,
        provider: impl ProvideAwsCredentials + Sync + Send + 'static,
    ) -> anyhow::Result<Option<Role>> {
        let client = IamClient::new_with(HttpClient::new()?, provider, Region::UsEast1);
        match client
            .get_role(GetRoleRequest {
                role_name: self.name().to_string(),
            })
            .await
        {
            Ok(response) => {
                let role = response.role;
                if role.arn == self.arn {
                    Ok(Some(role))
                } else {
                    // should we ever add cross AWS account support, we can remove this branch.
                    Err(anyhow::format_err!(
                        "AWS IAM Role {} is in different AWS Account, cannot access it",
                        self.arn,
                    ))
                }
            }
            // Role not found.
            Err(RusotoError::Service(GetRoleError::NoSuchEntity(_))) => Ok(None),
            Err(e) => Err(e)?,
        }
    }

    pub async fn patch_assume_role_policy<F>(
        &self,
        provider: impl ProvideAwsCredentials + Sync + Send + 'static,
        role: &Role,
        patcher: F,
    ) -> anyhow::Result<()>
    where
        F: FnOnce(&mut Vec<Statement>) -> anyhow::Result<()>,
    {
        let policy = role
            .assume_role_policy_document
            .as_deref()
            .unwrap_or(EMPTY_ASSUME_ROLE_POLICY);
        let original: PolicyDocument = serde_json::from_str(policy)?;
        let mut policy_document = original.clone();
        patcher(&mut policy_document.statement)?;
        if original != policy_document {
            let client = IamClient::new_with(HttpClient::new()?, provider, Region::UsEast1);
            let policy_document = serde_json::to_string(&policy_document)?;
            info!(
                "Update TrustPolicy on IAM Role {}\nOld: {}\n New: {}",
                role.arn, policy, policy_document
            );
            client
                .update_assume_role_policy(UpdateAssumeRolePolicyRequest {
                    role_name: role.role_name.clone(),
                    policy_document,
                })
                .await?;
        }
        Ok(())
    }

    fn match_statement(statement: &Statement, provider: &Provider) -> bool {
        let same_sid = statement.sid.as_deref() == Some(provider.statement_sid.as_str());
        let principals: Vec<String> = statement
            .principal
            .as_deref()
            .map(|p| p.clone().into_iter().collect())
            .unwrap_or_else(|| vec![]);
        let same_provider = principals.len() == 1
            && principals
                .iter()
                .find(|p| *p == &provider.provider_arn)
                .is_some();
        same_sid && same_provider
    }

    fn remove_stale_providers(tp: &TrustPolicyStatement, statements: &mut Vec<Statement>) {
        let mut stale_providers = tp
            .status
            .as_ref()
            .map(|s| s.providers.clone())
            .flatten()
            .unwrap_or_else(|| vec![]);
        stale_providers.retain(|p| {
            tp.spec
                .providers
                .iter()
                .find(|n| n.statement_sid == p.statement_sid && n.provider_arn == p.provider_arn)
                .is_none()
        });
        statements.retain(|v| {
            stale_providers
                .iter()
                .find(|p| Self::match_statement(v, p))
                .is_none()
        });
    }

    pub async fn add_trust_policy_statement(
        &self,
        provider: impl ProvideAwsCredentials + Sync + Send + 'static,
        tp: &TrustPolicyStatement,
        role: &Role,
    ) -> anyhow::Result<()> {
        self.patch_assume_role_policy(provider, role, move |statements| {
            // Remove all statements for stale providers, which are no longer in the spec.
            Self::remove_stale_providers(tp, statements);
            for provider in &tp.spec.providers {
                let arn: &str = provider.provider_arn.as_str();
                let provider_id = arn
                    .split(":oidc-provider/")
                    .last()
                    .ok_or_else(|| anyhow::format_err!("Invalid provider ARN {}", arn))?;
                statements.retain(|v| v.sid.as_deref() != Some(provider.statement_sid.as_str()));
                let mut conditions = Conditions::new();
                let mut string_equals = ConditionMap::new();
                string_equals.insert(
                    format!("{}:sub", provider_id),
                    format!(
                        "system:serviceaccount:{}:{}",
                        tp.namespace().as_deref().unwrap_or(""),
                        tp.spec.service_account_name
                    )
                    .into(),
                );
                conditions.insert("StringEquals".to_string(), string_equals);
                let statement = Statement {
                    sid: Some(provider.statement_sid.clone()),
                    effect: Effect::Allow,
                    action: Action::action("sts:AssumeRoleWithWebIdentity"),
                    principal: Some(Principal::federated(&[arn])),
                    condition: Some(conditions),
                    ..Default::default()
                };
                statements.push(statement);
            }
            Ok(())
        })
        .await
    }

    pub async fn remove_trust_policy_statement(
        &self,
        provider: impl ProvideAwsCredentials + Sync + Send + Clone + 'static,
        tp: &TrustPolicyStatement,
    ) -> anyhow::Result<()> {
        if let Some(role) = self.resolve(provider.clone()).await? {
            let sids: Vec<String> = tp
                .spec
                .providers
                .iter()
                .map(|p| p.statement_sid.clone())
                .collect();
            self.patch_assume_role_policy(provider, &role, move |statements| {
                // Remove all statements for stale providers, which are no longer in the spec.
                Self::remove_stale_providers(tp, statements);
                statements.retain(|v| {
                    sids.iter()
                        .find(|sid| Some(sid.as_str()) == v.sid.as_deref())
                        .is_none()
                });
                Ok(())
            })
            .await?;
        }
        Ok(())
    }
}

/// Controller which creates `TrustPolicyStatement` objects from `ServiceAccount` objects
/// that are annotated with an AWS IAM Role.
pub(crate) struct TrustPolicyStatementController {
    pub whoami: GetCallerIdentityResponse,
    pub provider: AutoRefreshingProvider<AwsCredentialsProvider>,
    pub configuration: Configuration,
    pub useage_policy_cache: Store<RoleUsagePolicy>,
}

struct ReconcileEvent {
    original: TrustPolicyStatement,
    pub modified: TrustPolicyStatement,
}

impl std::ops::Deref for ReconcileEvent {
    type Target = TrustPolicyStatement;

    fn deref(&self) -> &Self::Target {
        &self.modified
    }
}

impl DerefMut for ReconcileEvent {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.modified
    }
}

impl ReconcileEvent {
    pub fn new(original: TrustPolicyStatement) -> Self {
        let modified = original.clone();
        Self { original, modified }
    }

    pub fn namespace(&self) -> String {
        self.original.namespace().unwrap_or_else(|| "".to_string())
    }

    pub fn api(&self, client: Client) -> Api<TrustPolicyStatement> {
        if let Some(ns) = self.original.namespace() {
            Api::<TrustPolicyStatement>::namespaced(client, ns.as_str())
        } else {
            Api::<TrustPolicyStatement>::all(client)
        }
    }

    pub async fn update(&mut self, client: Client) -> kube::Result<()> {
        let namespace = self.original.namespace().unwrap_or("".to_string());
        // capture copy of modified for status diff.
        let modified = self.modified.clone();
        let spec_patch = {
            let mut ospec = self.original.clone();
            let mut mspec = self.modified.clone();
            ospec.status = None;
            mspec.status = None;
            let patch = diff(
                &serde_json::to_value(&ospec)?,
                &serde_json::to_value(&mspec)?,
            );
            if patch.0.is_empty() {
                None
            } else {
                Some(patch)
            }
        };
        let api = self.api(client);
        if let Some(patch) = spec_patch {
            let patch_txt = serde_json::to_string(&patch).unwrap();
            let response = api
                .patch(
                    self.original.name().as_str(),
                    &PatchParams {
                        field_manager: Some("iam.aws.rustrial.org".to_string()),
                        dry_run: false,
                        force: false,
                    },
                    &Patch::<json_patch::Patch>::Json(patch),
                )
                .await;
            info!(
                "Patch object {}/{} ({:?}) with {} -> {:?}",
                namespace,
                self.original.name(),
                self.original.resource_ver(),
                patch_txt,
                response
            );
            match response {
                Ok(new) => {
                    self.original = new.clone();
                    self.modified = new;
                }
                Err(e) => Err(e)?,
            }
        }
        let status_patch = {
            let patch = diff(
                &serde_json::to_value(&self.original.status)?,
                &serde_json::to_value(&modified.status)?,
            );
            if patch.0.is_empty() {
                None
            } else {
                Some(diff(
                    &serde_json::to_value(&self.original)?,
                    &serde_json::to_value(&modified)?,
                ))
            }
        };
        if let Some(patch) = status_patch {
            let patch_txt = serde_json::to_string(&patch).unwrap();
            let response = api
                .patch_status(
                    self.original.name().as_str(),
                    &PatchParams {
                        field_manager: Some("iam.aws.rustrial.org".to_string()),
                        dry_run: false,
                        force: false,
                    },
                    &Patch::<json_patch::Patch>::Json(patch),
                )
                .await;
            info!(
                "Patch object status {}/{} ({:?}) with {} -> {:?}",
                namespace,
                self.original.name(),
                self.original.resource_ver(),
                patch_txt,
                response
            );
            match response {
                Ok(new) => {
                    self.original = new.clone();
                    self.modified = new;
                }
                Err(e) => Err(e)?,
            }
        }
        Ok(())
    }
}

impl TrustPolicyStatementController {
    async fn reconcile_trust_policy(
        &self,
        tp: &mut ReconcileEvent,
    ) -> anyhow::Result<ReconcilerAction> {
        let namespace = tp.namespace();
        tp.set_status(None);
        //tp.metadata.managed_fields = None;
        let generation = tp.metadata.generation.clone();
        match IamRoleRef::try_from(tp.spec.role_arn.as_str()) {
            Ok(role_ref) => match role_ref.resolve(self.provider.clone()).await {
                Ok(Some(role)) => {
                    let authorizations = match self.get_authorizations(&tp, &role).await {
                        Ok(a) => a,
                        Err(e) => {
                            tp.set_status(Some(format!("{}", e)));
                            error!(
                                "Error while analysing authorization for {}/{}: {}",
                                namespace,
                                tp.name(),
                                e
                            );
                            vec![]
                        }
                    };
                    if authorizations.len() > 0 {
                        tp.set_authorizations(Some(authorizations));
                        // add finalizer and default values on spec
                        match self.prepare(tp).await {
                            Ok(_) => {
                                match role_ref
                                    .add_trust_policy_statement(self.provider.clone(), &tp, &role)
                                    .await
                                {
                                    Ok(_) => {
                                        let providers = tp.spec.providers.clone();
                                        tp.set_providers(Some(providers));
                                        tp.update_condition(Condition {
                                            type_: "Ready".to_string(),
                                            message: format!(""),
                                            reason: "Success".to_string(),
                                            status: "True".to_string(),
                                            observed_generation: generation,
                                            last_transition_time: None,
                                        })
                                    }
                                    Err(e) => tp.update_condition(Condition {
                                        type_: "Ready".to_string(),
                                        message: format!("UpdateAssumeRolePolicy failed: {}", e),
                                        reason: "UpdateAssumeRolePolicyFailed".to_string(),
                                        status: "False".to_string(),
                                        observed_generation: generation,
                                        last_transition_time: None,
                                    }),
                                }
                            }
                            // If preparation failed, propagate error without modifying status.
                            Err(e) => Err(e)?,
                        }
                    } else {
                        tp.set_authorizations(None);
                        if let Err(e) = role_ref
                            .remove_trust_policy_statement(self.provider.clone(), &tp)
                            .await
                        {
                            error!(
                                "Error while removing TrustPolicy Statement of {}/{} from IAM Role {}: {}",
                                namespace, tp.name(), role.arn, e
                            );
                            tp.set_status(Some(format!(
                                "Failed to remove TrustPolicy Statement from IAM Role: {}",
                                e
                            )));
                        } else {
                            tp.set_providers(None);
                        }
                        tp.update_condition(Condition {
                            type_: "Ready".to_string(),
                            message: format!(
                                "AWS IAM Role is not authorized for use in namespace {}",
                                namespace
                            ),
                            reason: "Unauthorized".to_string(),
                            status: "False".to_string(),
                            observed_generation: generation,
                            last_transition_time: None,
                        })
                    }
                }
                Ok(None) => tp.update_condition(Condition {
                    type_: "Ready".to_string(),
                    message: format!("AWS IAM Role {} does not exist.", role_ref.arn),
                    reason: "RoleDoesNotExist".to_string(),
                    status: "False".to_string(),
                    observed_generation: generation,
                    last_transition_time: None,
                }),
                Err(e) => tp.update_condition(Condition {
                    type_: "Ready".to_string(),
                    message: format!("Error while retrieving AWS IAM Role: {}", e),
                    reason: "Other".to_string(),
                    status: "False".to_string(),
                    observed_generation: generation,
                    last_transition_time: None,
                }),
            },
            Err(e) => tp.update_condition(Condition {
                type_: "Ready".to_string(),
                message: format!("{}", e),
                reason: "InvalidRoleArn".to_string(),
                status: "False".to_string(),
                observed_generation: generation,
                last_transition_time: None,
            }),
        };
        let action = ReconcilerAction {
            requeue_after: Some(Duration::from_secs(900)),
        };
        let response = tp.update(self.configuration.client.clone()).await;
        match response {
            Ok(_) => Ok(action),
            Err(Error::Api(e)) if e.code == 409 => Ok(ReconcilerAction {
                requeue_after: Some(Duration::from_secs(5)),
            }),
            Err(Error::Api(e)) if e.code == 404 => Ok(action),
            Err(e) => Err(e)?,
        }
    }

    async fn get_role_tags(&self, role: &Role) -> anyhow::Result<HashMap<String, String>> {
        let client =
            IamClient::new_with(HttpClient::new()?, self.provider.clone(), Region::UsEast1);
        let mut all_tags = HashMap::new();
        let mut lp = ListRoleTagsRequest {
            role_name: role.role_name.clone(),
            ..Default::default()
        };
        loop {
            let tags = client.list_role_tags(lp.clone()).await?;
            lp.marker = tags.marker;
            for tag in tags.tags {
                all_tags.insert(tag.key, tag.value);
            }
            if lp.marker.is_none() {
                break;
            }
        }
        Ok(all_tags)
    }

    pub(crate) fn arn_like(pattern: &str, arn: &str) -> bool {
        let pa = ARN::try_from(pattern);
        let a = ARN::try_from(arn);
        if let (Ok(arn_pattern), Ok(arn)) = (pa, a) {
            arn_pattern.matches(&arn)
        } else {
            pattern == arn || pattern == "*"
        }
    }

    pub(crate) fn tags_match(
        required_tags: &HashMap<String, String>,
        available_tags: &HashMap<String, String>,
    ) -> bool {
        for (key, value) in required_tags {
            if available_tags.get(key) != Some(value) {
                return false;
            }
        }
        true
    }

    pub(crate) fn matches(
        policy: &RoleUsagePolicySpec,
        namespace: &str,
        role_arn: &str,
        permission_boundary: Option<String>,
        available_tags: &HashMap<String, String>,
    ) -> bool {
        let ns = policy
            .namespaces
            .iter()
            .filter(|ns| ns.as_str() == "*" || ns.as_str() == namespace)
            .count()
            > 0;
        if ns {
            let role_arn_matches = Self::arn_like(policy.role_arn.as_str(), role_arn);
            let tags_match = match policy.role_tags.as_ref().filter(|v| !v.is_empty()) {
                Some(required_tags) => Self::tags_match(required_tags, &available_tags),
                // if no tags are provided, they match
                None => true,
            };
            let permission_boundary_matches = match (
                &policy.permission_boundary.as_deref(),
                permission_boundary.as_deref(),
            ) {
                (Some(pattern), Some(arn)) if !pattern.is_empty() => Self::arn_like(pattern, arn),
                (Some(pattern), None) if !pattern.is_empty() => false,
                // match all permission boundaries (including empty one) if spec.permission_boundary is
                // not set.
                _ => true,
            };
            role_arn_matches && tags_match && permission_boundary_matches
        } else {
            false
        }
    }

    async fn get_authorizations(
        &self,
        tp: &TrustPolicyStatement,
        role: &Role,
    ) -> anyhow::Result<Vec<Authorization>> {
        let namespace = tp.namespace().unwrap_or_else(|| "".to_string());
        let cache = self.useage_policy_cache.state();
        let available_tags = self.get_role_tags(role).await?;
        let authorizations = cache
            .iter()
            .filter(|p: &&RoleUsagePolicy| {
                Self::matches(
                    &p.spec,
                    namespace.as_str(),
                    role.arn.as_str(),
                    role.permissions_boundary
                        .as_ref()
                        .map(|v| v.permissions_boundary_arn.clone())
                        .flatten(),
                    &available_tags,
                )
            })
            .map(|v| Authorization {
                kind: v.kind.clone(),
                name: v.name(),
                namespace: v.namespace(),
            })
            .collect();
        Ok(authorizations)
    }

    async fn prepare(&self, tp: &mut ReconcileEvent) -> anyhow::Result<()> {
        // Add finalizer
        let mut finalizers = tp.metadata.finalizers.take().unwrap_or(vec![]);
        finalizers.push(FINALIZER.to_string());
        finalizers.dedup();
        tp.metadata.finalizers = Some(finalizers);
        //tp.metadata.managed_fields = None;
        Ok(())
    }

    async fn remove_statement(&self, tp: &mut TrustPolicyStatement) -> anyhow::Result<()> {
        let role_ref = IamRoleRef::try_from(tp.spec.role_arn.as_str());
        match role_ref {
            // If ARN is syntactically valid, remove trust policy from Role.
            Ok(role_ref) => {
                role_ref
                    .remove_trust_policy_statement(self.provider.clone(), tp)
                    .await?
            }
            // If ARN is syntactically invalid, we do not need to remove anything.
            Err(_) => (),
        }
        Ok(())
    }

    async fn cleanup(&self, tp: &mut ReconcileEvent) -> anyhow::Result<ReconcilerAction> {
        debug!(
            "cleanup TrustPolicyStatement {}/{}",
            tp.namespace(),
            tp.name(),
        );
        let action = ReconcilerAction {
            requeue_after: Some(Duration::from_secs(900)),
        };
        //tp.metadata.managed_fields = None;
        match self.remove_statement(tp).await {
            Ok(_) => {
                // remove status
                tp.status = None;
                // remove finalizer
                if let Some(finalizers) = &mut tp.metadata.finalizers {
                    finalizers.retain(|v| v != FINALIZER);
                }
            }
            Err(e) => {
                // patch status to make error visible
                tp.set_status(Some(format!("{}", e)));
            }
        }
        let response = tp.update(self.configuration.client.clone()).await;
        match response {
            Ok(_) => Ok(action),
            Err(Error::Api(e)) if e.code == 409 => Ok(ReconcilerAction {
                requeue_after: Some(Duration::from_secs(5)),
            }),
            Err(Error::Api(e)) if e.code == 404 => Ok(action),
            Err(e) => Err(e)?,
        }
    }

    /// Controller triggers this whenever our main object or our children changed
    async fn reconcile(
        tp: TrustPolicyStatement,
        ctx: Ctx<Self>,
    ) -> Result<ReconcilerAction, CrdError> {
        let start = Instant::now();
        let mut event = ReconcileEvent::new(tp);
        let result = if event.metadata.deletion_timestamp.is_some() {
            // If TrustPolicyStatement has been deleted, remove trust policy statement from AWS IAM Role.
            ctx.get_ref()
                .cleanup(&mut event)
                .await
                .map_err(|e| CrdError::from(e))
        } else {
            info!(
                "reconile TrustPolicyStatement {}/{} with AWS IAM Role ARN {}",
                event.namespace(),
                event.name(),
                event.spec.role_arn,
            );
            ctx.get_ref()
                .reconcile_trust_policy(&mut event)
                .await
                .map_err(|e| CrdError::from(e))
        };
        let duration = Instant::now() - start;
        histogram!(
            "reconcile_aws_iam_trustpolicy_duration_ns",
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

    fn might_affect(p: &RoleUsagePolicy, tp: &TrustPolicyStatement) -> bool {
        let ns = p
            .spec
            .namespaces
            .iter()
            .filter(|ns| ns.as_str() == "*" || Some(ns.as_str()) == tp.namespace().as_deref())
            .count()
            > 0;
        let matches = ns && Self::arn_like(p.spec.role_arn.as_str(), tp.spec.role_arn.as_str());
        if let Some(status) = &tp.status {
            if let Some(authorizations) = &status.authorizations {
                let currently_authorized_by = authorizations
                    .iter()
                    .find(|a: &&Authorization| {
                        a.kind == "RoleUsagePolicy"
                            && a.namespace == p.namespace()
                            && a.name == p.name()
                    })
                    .is_some();
                matches || currently_authorized_by
            } else {
                matches
            }
        } else {
            matches
        }
    }

    fn mapper_impl(
        policy: RoleUsagePolicy,
        sa_cache: &Store<TrustPolicyStatement>,
    ) -> Vec<ObjectRef<TrustPolicyStatement>> {
        let affected = sa_cache
            .state()
            .into_iter()
            .filter(|sa| Self::might_affect(&policy, sa))
            .map(|sa| ObjectRef::from_obj(&sa))
            .collect();
        info!(
            "RoleUsagePolicy change detected: {:?} which might affect {:?}",
            policy, affected
        );
        affected
    }

    pub fn start(self) -> impl Future<Output = ()> {
        let controller = Controller::new(
            self.configuration.trust_policy_statment.clone(),
            ListParams::default(),
        );
        let cache = controller.store();
        let mapper = move |policy: RoleUsagePolicy| Self::mapper_impl(policy, &cache);
        let controller = controller
            .watches(
                self.configuration.role_usage_policy.clone(),
                ListParams::default(),
                mapper,
            )
            .run(Self::reconcile, Self::error_policy, Ctx::new(self))
            .for_each(|res| async move {
                match res {
                    Ok(o) => {
                        counter!("reconcile_aws_iam_trustpolicy_success", 1);
                        info!("reconciled {:?}", o)
                    }
                    Err(e) => {
                        counter!("reconcile_aws_iam_trustpolicy_failure", 1);
                        warn!("reconcile failed: {}", e)
                    }
                }
            });
        controller
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches() {
        let policy = RoleUsagePolicySpec {
            role_arn: "xx".to_string(),
            role_tags: None,
            permission_boundary: None,
            namespaces: vec!["aa".to_string()],
        };
        assert!(TrustPolicyStatementController::matches(
            &policy,
            "aa",
            "xx",
            None,
            &HashMap::new()
        ));
        let policy = RoleUsagePolicySpec {
            role_arn: "*".to_string(),
            role_tags: None,
            permission_boundary: None,
            namespaces: vec!["aa".to_string()],
        };
        assert!(TrustPolicyStatementController::matches(
            &policy,
            "aa",
            "xx",
            None,
            &HashMap::new()
        ));
    }

    #[test]
    fn matches_permission_boundary() {
        let full = "arn:aws:iam::000000000000:policy/name";
        let policy = RoleUsagePolicySpec {
            role_arn: "*".to_string(),
            role_tags: None,
            permission_boundary: Some(full.to_string()),
            namespaces: vec!["*".to_string()],
        };
        assert!(TrustPolicyStatementController::matches(
            &policy,
            "aa",
            "xx",
            Some(full.to_string()),
            &HashMap::new()
        ));
        let policy = RoleUsagePolicySpec {
            role_arn: "*".to_string(),
            role_tags: None,
            permission_boundary: Some("arn:aws:iam::*:policy/name".to_string()),
            namespaces: vec!["*".to_string()],
        };
        assert!(TrustPolicyStatementController::matches(
            &policy,
            "aa",
            "xx",
            Some(full.to_string()),
            &HashMap::new()
        ));
        let policy = RoleUsagePolicySpec {
            role_arn: "*".to_string(),
            role_tags: None,
            permission_boundary: Some("arn:aws:iam::*:policy/*".to_string()),
            namespaces: vec!["*".to_string()],
        };
        assert!(TrustPolicyStatementController::matches(
            &policy,
            "aa",
            "xx",
            Some(full.to_string()),
            &HashMap::new()
        ));
    }

    #[test]
    fn refuses_permission_boundary() {
        let policy = RoleUsagePolicySpec {
            role_arn: "*".to_string(),
            role_tags: None,
            permission_boundary: Some("arn:aws:iam::*:policy/name".to_string()),
            namespaces: vec!["aa".to_string()],
        };
        assert!(!TrustPolicyStatementController::matches(
            &policy,
            "aa",
            "xx",
            None,
            &HashMap::new()
        ));
        assert!(!TrustPolicyStatementController::matches(
            &policy,
            "aa",
            "xx",
            Some("arn:aws:iam::00000000000000:policy/other-name".to_string()),
            &HashMap::new()
        ));
    }

    #[test]
    fn matches_namespace() {
        let policy = RoleUsagePolicySpec {
            role_arn: "*".to_string(),
            role_tags: None,
            permission_boundary: None,
            namespaces: vec!["aa".to_string(), "bb".to_string()],
        };
        assert!(TrustPolicyStatementController::matches(
            &policy,
            "bb",
            "xx",
            None,
            &HashMap::new()
        ));
    }

    #[test]
    fn matches_namespace_wildcard() {
        let policy = RoleUsagePolicySpec {
            role_arn: "*".to_string(),
            role_tags: None,
            permission_boundary: None,
            namespaces: vec!["*".to_string()],
        };
        assert!(TrustPolicyStatementController::matches(
            &policy,
            "bb",
            "xx",
            None,
            &HashMap::new()
        ));
    }

    #[test]
    fn refuses_namespace() {
        let policy = RoleUsagePolicySpec {
            role_arn: "*".to_string(),
            role_tags: None,
            permission_boundary: Some("arn:aws:iam::*:policy/name".to_string()),
            namespaces: vec!["aa".to_string()],
        };
        assert!(!TrustPolicyStatementController::matches(
            &policy,
            "bb",
            "xx",
            None,
            &HashMap::new()
        ));
    }

    #[test]
    fn refuses() {
        let policy = RoleUsagePolicySpec {
            role_arn: "xx".to_string(),
            role_tags: None,
            permission_boundary: None,
            namespaces: vec!["aa".to_string()],
        };
        assert!(!TrustPolicyStatementController::matches(
            &policy,
            "aa",
            "yy",
            None,
            &HashMap::new()
        ));
    }

    #[test]
    fn matches_role_tags_empty() {
        let required = HashMap::new();
        let available = HashMap::new();
        assert!(TrustPolicyStatementController::tags_match(
            &required, &available
        ));
    }

    #[test]
    fn matches_role_tags_superset() {
        let mut required = HashMap::new();
        required.insert("a".to_string(), "v1".to_string());
        required.insert("b".to_string(), "v2".to_string());
        let mut available = HashMap::new();
        available.insert("a".to_string(), "v1".to_string());
        available.insert("b".to_string(), "v2".to_string());
        available.insert("c".to_string(), "v3".to_string());
        assert!(TrustPolicyStatementController::tags_match(
            &required, &available
        ));
    }

    #[test]
    fn refuse_role_tags_empty() {
        let mut required = HashMap::new();
        required.insert("a".to_string(), "v1".to_string());
        required.insert("b".to_string(), "v2".to_string());
        let available = HashMap::new();
        assert!(!TrustPolicyStatementController::tags_match(
            &required, &available
        ));
    }

    #[test]
    fn refuse_role_tags_subset() {
        let mut required = HashMap::new();
        required.insert("a".to_string(), "v1".to_string());
        required.insert("b".to_string(), "v2".to_string());
        let mut available = HashMap::new();
        available.insert("a".to_string(), "v1".to_string());
        assert!(!TrustPolicyStatementController::tags_match(
            &required, &available
        ));
    }

    #[test]
    fn refuse_role_tags_different_value() {
        let mut required = HashMap::new();
        required.insert("a".to_string(), "v1".to_string());
        let mut available = HashMap::new();
        available.insert("a".to_string(), "v2".to_string());
        assert!(!TrustPolicyStatementController::tags_match(
            &required, &available
        ));
    }
}
