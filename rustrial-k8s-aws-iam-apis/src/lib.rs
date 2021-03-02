use std::collections::HashMap;

use k8s_openapi::chrono::{SecondsFormat, Utc};
use kube::CustomResource;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const API_VERSION: &'static str = "iam.aws.rustrial.org/v1alpha1";

pub const API_GROUP: &'static str = "iam.aws.rustrial.org";

pub const VERSION: &'static str = "v1alpha1";

pub const TRUST_POLICY_STATEMENT_LABEL: &'static str =
    "iam.aws.rustrial.org/trust-policy-statement";

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
pub struct Condition {
    /// lastTransitionTime is the last time the condition transitioned from one status to another. This should be when the underlying condition changed.  If that is not known, then using the time when the API field changed is acceptable.
    #[serde(rename = "lastTransitionTime")]
    pub last_transition_time: Option<String>,

    /// message is a human readable message indicating details about the transition. This may be an empty string.
    pub message: String,

    /// observedGeneration represents the .metadata.generation that the condition was set based upon. For instance, if .metadata.generation is currently 12, but the .status.conditions\[x\].observedGeneration is 9, the condition is out of date with respect to the current state of the instance.
    #[serde(rename = "observedGeneration")]
    pub observed_generation: Option<i64>,

    /// reason contains a programmatic identifier indicating the reason for the condition's last transition. Producers of specific condition types may define expected values and meanings for this field, and whether the values are considered a guaranteed API. The value should be a CamelCase string. This field may not be empty.
    pub reason: String,

    /// status of the condition, one of True, False, Unknown.
    pub status: String,

    /// type of condition in CamelCase or in foo.example.com/CamelCase.
    #[serde(rename = "type")]
    pub type_: String,
}

/// `RoleUsagePolicy` objects are managed by Cluster Administrator to authorize
/// namespaces to use (assume) certain AWS IAM Roles. The controller will not
/// add any TrustPolicy Statements to AWS IAM Roles if there is no valid
/// authorization for the corresponding `TrustPolicyStatement` object.
#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "iam.aws.rustrial.org",
    version = "v1alpha1",
    kind = "RoleUsagePolicy",
    derive = "PartialEq",
    status = "RoleUsagePolicyStatus",
    namespaced
)]
pub struct RoleUsagePolicySpec {
    /// AWS IAM Role ARN of the role for which to grant permission.
    /// Either a full ARN, am ARN-PATTERN or the wildcard `*` to match all ARNs.
    /// - `arn:aws:iam::000000000000:role/path/role-name`
    /// - `arn:aws:iam::*:role/path/role-name`
    /// - `arn:aws:iam::*:role/path/*`
    /// - `*`
    #[serde(rename = "roleArn")]
    pub role_arn: String,
    /// ARN or ARN-Pattern of the AWS PermissionBoundary Policy.
    #[serde(rename = "permissionBoundary", skip_serializing_if = "Option::is_none")]
    pub permission_boundary: Option<String>,

    /// Role tags, which must match for the policy to apply.
    #[serde(rename = "roleTags", skip_serializing_if = "Option::is_none")]
    pub role_tags: Option<HashMap<String, String>>,

    /// Set of Kubernetes namespaces, which are authorized to use that AWS IAM    
    /// Role. Can contain `*` to authorize all namespaces.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, JsonSchema)]
pub struct RoleUsagePolicyStatus {}

#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "iam.aws.rustrial.org",
    version = "v1alpha1",
    kind = "TrustPolicyStatement",
    derive = "PartialEq",
    status = "TrustPolicyStatementStatus",
    namespaced,
    printcolumn = r#"{
        "name":"Ready", 
        "type": "string", 
        "jsonPath": ".status.conditions[?(@.type==\"Ready\")].status", 
        "description": "Whether TrustPolicyStatement is ready or not. It is considered ready if it has been successfully synced with AWS, which implies that it is authorized as well. "
    }"#
)]
pub struct TrustPolicyStatementSpec {
    /// ServiceAccount name for which this statement was created.
    #[serde(rename = "serviceAccountName")]
    pub service_account_name: String,
    /// AWS IAM Role ARN this statement is applied to.
    #[serde(rename = "roleArn")]
    pub role_arn: String,
    /// AWS IAM OpenID Connect Provider ARN
    #[serde(rename = "providerArn")]
    pub provider_arn: String,
    /// Trust Policy Statement ID (SID).
    #[serde(rename = "statementSid")]
    pub statement_sid: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, JsonSchema)]
pub struct Authorization {
    /// The kind of the resource which provided authorization.
    pub kind: String,
    /// The name of the resource which provided authorization.
    pub name: String,
    /// The namespace of the resource which provided authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, JsonSchema)]
pub struct TrustPolicyStatementStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    /// The authorization sources which authorize the use of this trust policy statement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorizations: Option<Vec<Authorization>>,
    /// Status text
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

impl Default for TrustPolicyStatementStatus {
    fn default() -> Self {
        Self {
            conditions: None,
            authorizations: None,
            status: None,
        }
    }
}

impl TrustPolicyStatement {
    pub fn set_status(&mut self, text: Option<String>) {
        let mut status = self
            .status
            .take()
            .unwrap_or_else(|| TrustPolicyStatementStatus::default());
        status.status = text;
        self.status = Some(status);
    }

    pub fn update_condition(&mut self, c: Condition) {
        let mut status = self
            .status
            .take()
            .unwrap_or_else(|| TrustPolicyStatementStatus::default());
        status.update_condition(c);
        self.status = Some(status);
    }

    pub fn set_authorizations(&mut self, authorizations: Option<Vec<Authorization>>) {
        let mut status = self
            .status
            .take()
            .unwrap_or_else(|| TrustPolicyStatementStatus::default());
        status.authorizations = authorizations;
        self.status = Some(status);
    }
}

impl TrustPolicyStatementStatus {
    pub fn update_condition(&mut self, mut c: Condition) {
        let time = Utc::now();
        c.last_transition_time = Some(time.to_rfc3339_opts(SecondsFormat::Secs, true));
        let mut conditions: Vec<Condition> = self.conditions.take().unwrap_or_else(|| vec![]);
        if let Some(existing) = conditions.iter().find(|c| c.type_ == c.type_) {
            if existing.status != c.status
                || existing.reason != c.reason
                || existing.message != c.message
                || existing.observed_generation != c.observed_generation
            {
                conditions.retain(|v| v.type_ != c.type_);
                conditions.push(c);
            }
        } else {
            conditions.push(c);
        };
        self.conditions = Some(conditions);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let p = RoleUsagePolicySpec {
            role_arn: "xx".to_string(),
            role_tags: None,
            permission_boundary: None,
            namespaces: vec!["aa".to_string()],
        };
        assert_eq!(
            r#"{"roleArn":"xx","namespaces":["aa"]}"#,
            serde_json::to_string(&p).unwrap()
        );
        assert_eq!(2 + 2, 4);
    }
}
