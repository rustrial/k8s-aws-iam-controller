use std::time::Duration;

use crate::{
    env_var,
    iam_policy::{PolicyDocument, Principal, PrincipalKind, Values},
    AwsCredentialsProvider,
};
use lazy_static::lazy_static;
use log::warn;
use metrics::gauge;
use regex::Regex;
use rusoto_core::{credential::AutoRefreshingProvider, HttpClient, Region};
use rusoto_iam::{
    Iam, IamClient, ListOpenIDConnectProvidersRequest, ListRolesRequest, Role,
    UpdateAssumeRolePolicyRequest,
};

lazy_static! {
    static ref PROVIDER_ARN: Regex = Regex::new(
        r#"^arn:aws:iam::(\d+):oidc-provider/(oidc\.eks\.[^.]+\.amazonaws\.com/id/.*)$"#
    )
    .unwrap();
}

pub struct GarbageCollector {
    pub provider: AutoRefreshingProvider<AwsCredentialsProvider>,
}

struct Candidate {
    pub role: Role,
    pub policy: PolicyDocument,
    pub stale_providers: Vec<String>,
}

impl GarbageCollector {
    pub async fn provider_arns(&self, client: &IamClient) -> anyhow::Result<Vec<String>> {
        let providers = client
            .list_open_id_connect_providers(ListOpenIDConnectProvidersRequest::default())
            .await?;
        Ok(providers
            .open_id_connect_provider_list
            .unwrap_or_else(|| vec![])
            .into_iter()
            .flat_map(|p| p.arn)
            .collect())
    }

    async fn mark(&self, client: &IamClient) -> anyhow::Result<(usize, usize, Vec<Candidate>)> {
        let providers = self.provider_arns(&client).await?;
        let mut lp = ListRolesRequest::default();
        let mut candidates: Vec<Candidate> = vec![];
        let mut scanned_roles = 0usize;
        let mut scanned_statements = 0usize;
        loop {
            let roles = client.list_roles(lp.clone()).await?;
            scanned_roles += roles.roles.len();
            for role in roles.roles {
                if let Some(raw_policy_document) = &role.assume_role_policy_document {
                    let pd = serde_json::from_str::<PolicyDocument>(raw_policy_document.as_str());
                    match pd {
                        Ok(policy_document) => {
                            let mut stale_providers = vec![];
                            for s in &policy_document.statement {
                                scanned_statements += 1;
                                if let Some(p) = &s.principal {
                                    match p {
                                        Principal::Principal {
                                            principal:
                                                PrincipalKind::Federated(Values::One(provider_arn)),
                                        } => {
                                            //
                                            if let (Some(captures), Some(role_captures)) = (
                                                PROVIDER_ARN.captures(provider_arn.as_str()),
                                                crate::trust_policy_statement_controller::ROLE_ARN
                                                    .captures(role.arn.as_str()),
                                            ) {
                                                let same_account = captures[1] == role_captures[1];
                                                if same_account
                                                    && s.sid.is_some()
                                                    && providers
                                                        .iter()
                                                        .find(|p| {
                                                            p.as_str() == provider_arn.as_str()
                                                        })
                                                        .is_none()
                                                {
                                                    stale_providers.push(provider_arn.to_string());
                                                }
                                            }
                                        }
                                        _ => (),
                                    }
                                }
                            }
                            if !stale_providers.is_empty() {
                                candidates.push(Candidate {
                                    role: role,
                                    stale_providers,
                                    policy: policy_document.clone(),
                                });
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Error parsing Trust Policy of IAM Role {}: {} {}",
                                role.arn, e, raw_policy_document
                            );
                        }
                    }
                }
            }
            lp.marker = roles.marker;
            if lp.marker.is_none() {
                break;
            }
        }
        Ok((scanned_roles, scanned_statements, candidates))
    }

    async fn sweap(&self, client: &IamClient, candidates: Vec<Candidate>) -> anyhow::Result<usize> {
        let providers = self.provider_arns(&client).await?;
        let mut sweaped = 0usize;
        for mut candidate in candidates {
            // Only retain stale providers, if they are still not in the provider list.
            candidate
                .stale_providers
                .retain(|p| providers.iter().find(|id| *id == p).is_none());
            if !candidate.stale_providers.is_empty() {
                let stale = &candidate.stale_providers;
                let before = candidate.policy.statement.len();
                candidate.policy.statement.retain(|s| {
                    //TODO
                    match &s.principal {
                        Some(Principal::Principal {
                            principal: PrincipalKind::Federated(Values::One(f)),
                        }) => !stale.contains(f),
                        _ => true,
                    }
                });
                let after = candidate.policy.statement.len();
                let removed_statements = before - after;
                if removed_statements > 0 {
                    match serde_json::to_string(&candidate.policy) {
                        Ok(txt) => {
                            info!(
                                "Update Trust Policy of Role {}, removing {} statements -> {}",
                                candidate.role.arn, removed_statements, txt
                            );
                            let response = client
                                .update_assume_role_policy(UpdateAssumeRolePolicyRequest {
                                    role_name: candidate.role.role_name,
                                    policy_document: txt,
                                })
                                .await;
                            //let response: anyhow::Result<()> = Ok(()); //TODO uncomment above
                            match response {
                                Ok(_) => {
                                    sweaped += removed_statements;
                                }
                                Err(e) => warn!("{}", e),
                            }
                        }
                        Err(e) => warn!("{}", e),
                    }
                }
            }
        }
        Ok(sweaped)
    }

    async fn run(&self) -> anyhow::Result<()> {
        let client =
            IamClient::new_with(HttpClient::new()?, self.provider.clone(), Region::UsEast1);
        let (scanned_roles, scanned_statements, candidates) = self.mark(&client).await?;
        let sweaped = self.sweap(&client, candidates).await?;
        info!(
            "TrustPolicy GC: scanned: {} roles and {} statements, sweaped: {} statements",
            scanned_roles, scanned_statements, sweaped
        );
        gauge!("awsiamcontroller_gc_scanned_roles", scanned_roles as f64);
        gauge!(
            "awsiamcontroller_gc_scanned_statements",
            scanned_statements as f64
        );
        gauge!("awsiamcontroller_gc_sweaped_statements", sweaped as f64);
        Ok(())
    }

    pub async fn start(self) {
        let ival: u64 = env_var("TRUST_POLICY_STATEMENT_GC_INTERVAL_SECONDS")
            .map(|i| i.parse::<u64>().ok())
            .flatten()
            // Run GC once per hour by default
            .unwrap_or(60 * 60);
        let mut interval = tokio::time::interval(Duration::from_secs(ival));
        let disabled = env_var("DISABLE_TRUST_POLICY_STATEMENT_GC");
        loop {
            interval.tick().await;
            if disabled.is_none() {
                match self.run().await {
                    Ok(_) => (),
                    Err(e) => warn!("TrustPolicy GC error: {}", e),
                }
            }
        }
    }
}
