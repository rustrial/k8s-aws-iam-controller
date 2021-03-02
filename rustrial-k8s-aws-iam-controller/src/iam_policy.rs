use std::{collections::HashMap, iter::FromIterator};

use serde::{Deserialize, Serialize};

/// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Effect {
    Deny,
    Allow,
}

impl Default for Effect {
    fn default() -> Self {
        Self::Allow
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Values {
    One(String),
    Many(Vec<String>),
}

impl Values {
    pub fn one<S: ToString>(p: S) -> Values {
        Values::One(p.to_string())
    }

    pub fn many<S: ToString, V: IntoIterator<Item = S>>(p: V) -> Values {
        Values::Many(p.into_iter().map(|v| v.to_string()).collect())
    }

    pub fn into_many(self) -> Self {
        match self {
            Values::One(v) => Values::Many(vec![v]),
            me => me,
        }
    }
}

impl IntoIterator for Values {
    type Item = String;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Values::One(one) => vec![one].into_iter(),
            Values::Many(many) => many.into_iter(),
        }
    }
}

/// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrincipalKind {
    AWS(Values),
    Federated(Values),
    Service(Values),
    CanonicalUser(Values),
    #[serde(rename = "*")]
    All,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Principal {
    Principal {
        #[serde(rename = "Principal")]
        principal: PrincipalKind,
    },
    NotPrincipal {
        #[serde(rename = "NotPrincipal")]
        principal: PrincipalKind,
    },
}

impl PrincipalKind {
    pub fn aws<S: ToString, V: IntoIterator<Item = S>>(p: V) -> PrincipalKind {
        PrincipalKind::AWS(Values::many(p))
    }

    pub fn service<S: ToString, V: IntoIterator<Item = S>>(p: V) -> PrincipalKind {
        PrincipalKind::Service(Values::many(p))
    }

    pub fn federated<S: ToString, V: IntoIterator<Item = S>>(p: V) -> PrincipalKind {
        PrincipalKind::Federated(Values::many(p))
    }

    pub fn canonical_user<S: ToString, V: IntoIterator<Item = S>>(p: V) -> PrincipalKind {
        PrincipalKind::CanonicalUser(Values::many(p))
    }
}

impl Principal {
    pub fn aws<S: ToString, V: IntoIterator<Item = S>>(p: V) -> Principal {
        Principal::Principal {
            principal: PrincipalKind::AWS(Values::many(p)),
        }
    }

    pub fn not_aws<S: ToString, V: IntoIterator<Item = S>>(p: V) -> Principal {
        Principal::NotPrincipal {
            principal: PrincipalKind::AWS(Values::many(p)),
        }
    }

    pub fn service<S: ToString, V: IntoIterator<Item = S>>(p: V) -> Principal {
        Principal::Principal {
            principal: PrincipalKind::Service(Values::many(p)),
        }
    }

    pub fn not_service<S: ToString, V: IntoIterator<Item = S>>(p: V) -> Principal {
        Principal::NotPrincipal {
            principal: PrincipalKind::Service(Values::many(p)),
        }
    }

    pub fn federated<S: ToString, V: IntoIterator<Item = S>>(p: V) -> Principal {
        Principal::Principal {
            principal: PrincipalKind::Federated(Values::many(p)),
        }
    }

    pub fn not_federated<S: ToString, V: IntoIterator<Item = S>>(p: V) -> Principal {
        Principal::NotPrincipal {
            principal: PrincipalKind::Federated(Values::many(p)),
        }
    }

    pub fn canonical_user<S: ToString, V: IntoIterator<Item = S>>(p: V) -> Principal {
        Principal::Principal {
            principal: PrincipalKind::CanonicalUser(Values::many(p)),
        }
    }

    pub fn not_canonical_user<S: ToString, V: IntoIterator<Item = S>>(p: V) -> Principal {
        Principal::NotPrincipal {
            principal: PrincipalKind::CanonicalUser(Values::many(p)),
        }
    }

    pub fn all() -> Principal {
        Principal::Principal {
            principal: PrincipalKind::All,
        }
    }

    pub fn not_all() -> Principal {
        Principal::Principal {
            principal: PrincipalKind::All,
        }
    }
}

impl std::ops::Not for Principal {
    type Output = Principal;

    fn not(self) -> Self::Output {
        match self {
            Principal::Principal { principal } => Principal::NotPrincipal { principal },
            Principal::NotPrincipal { principal } => Principal::Principal { principal },
        }
    }
}

impl std::ops::Deref for Principal {
    type Target = PrincipalKind;

    fn deref(&self) -> &Self::Target {
        match self {
            Principal::Principal { principal } => principal,
            Principal::NotPrincipal { principal } => principal,
        }
    }
}

impl AsRef<PrincipalKind> for Principal {
    fn as_ref(&self) -> &PrincipalKind {
        match self {
            Principal::Principal { principal } => principal,
            Principal::NotPrincipal { principal } => principal,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Action {
    Action {
        #[serde(rename = "Action")]
        action: Values,
    },
    NotAction {
        #[serde(rename = "NotAction")]
        action: Values,
    },
}

impl Action {
    pub fn action<S: ToString>(p: S) -> Action {
        Action::Action {
            action: Values::one(p),
        }
    }

    pub fn actions<S: ToString, V: IntoIterator<Item = S>>(p: V) -> Action {
        Action::Action {
            action: Values::many(p),
        }
    }

    pub fn not_action<S: ToString>(p: S) -> Action {
        Action::NotAction {
            action: Values::one(p),
        }
    }

    pub fn not_actions<S: ToString, V: IntoIterator<Item = S>>(p: V) -> Action {
        Action::NotAction {
            action: Values::many(p),
        }
    }
}

impl std::ops::Not for Action {
    type Output = Action;

    fn not(self) -> Self::Output {
        match self {
            Action::Action { action } => Action::NotAction { action },
            Action::NotAction { action } => Action::Action { action },
        }
    }
}

impl std::ops::Deref for Action {
    type Target = Values;

    fn deref(&self) -> &Self::Target {
        match self {
            Action::Action { action } => action,
            Action::NotAction { action } => action,
        }
    }
}

impl AsRef<Values> for Action {
    fn as_ref(&self) -> &Values {
        match self {
            Action::Action { action } => action,
            Action::NotAction { action } => action,
        }
    }
}

impl<A> From<A> for Action
where
    A: ToString,
{
    fn from(action: A) -> Self {
        Action::action(action)
    }
}

impl<A> FromIterator<A> for Action
where
    A: ToString,
{
    fn from_iter<T: IntoIterator<Item = A>>(iter: T) -> Self {
        Action::actions::<A, T>(iter)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Resource {
    Resource {
        #[serde(rename = "Resource")]
        resource: Values,
    },
    NotResource {
        #[serde(rename = "NotResource")]
        resource: Values,
    },
}

impl Resource {
    pub fn resource<S: ToString>(p: S) -> Resource {
        Resource::Resource {
            resource: Values::one(p),
        }
    }

    pub fn resources<S: ToString, V: IntoIterator<Item = S>>(p: V) -> Resource {
        Resource::Resource {
            resource: Values::many(p),
        }
    }

    pub fn not_resource<S: ToString>(p: S) -> Resource {
        Resource::NotResource {
            resource: Values::one(p),
        }
    }

    pub fn not_resources<S: ToString, V: IntoIterator<Item = S>>(p: V) -> Resource {
        Resource::NotResource {
            resource: Values::many(p),
        }
    }
}

impl std::ops::Not for Resource {
    type Output = Resource;

    fn not(self) -> Self::Output {
        match self {
            Resource::Resource { resource } => Resource::NotResource { resource },
            Resource::NotResource { resource } => Resource::Resource { resource },
        }
    }
}

impl std::ops::Deref for Resource {
    type Target = Values;

    fn deref(&self) -> &Self::Target {
        match self {
            Resource::Resource { resource } => resource,
            Resource::NotResource { resource } => resource,
        }
    }
}

impl AsRef<Values> for Resource {
    fn as_ref(&self) -> &Values {
        match self {
            Resource::Resource { resource } => resource,
            Resource::NotResource { resource } => resource,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ScalarValue {
    String(String),
    Number(f64),
    Boolean(bool),
}

impl From<String> for ScalarValue {
    fn from(v: String) -> Self {
        ScalarValue::String(v)
    }
}

impl From<bool> for ScalarValue {
    fn from(v: bool) -> Self {
        ScalarValue::Boolean(v)
    }
}

impl From<f64> for ScalarValue {
    fn from(v: f64) -> Self {
        ScalarValue::Number(v)
    }
}

impl From<i32> for ScalarValue {
    fn from(v: i32) -> Self {
        ScalarValue::Number(v as f64)
    }
}

impl From<u32> for ScalarValue {
    fn from(v: u32) -> Self {
        ScalarValue::Number(v as f64)
    }
}

impl<T> From<T> for ConditionValues
where
    T: Into<ScalarValue>,
{
    fn from(v: T) -> Self {
        ConditionValues::One(v.into())
    }
}

/// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ConditionValues {
    One(ScalarValue),
    Many(Vec<ScalarValue>),
}
pub type ConditionMap = HashMap<String, ConditionValues>;

pub type Conditions = HashMap<String, ConditionMap>;

///
/// ```
/// Statement::new()
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Statement {
    #[serde(rename = "Sid", skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,

    #[serde(rename = "Effect")]
    pub effect: Effect,

    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub principal: Option<Principal>,

    #[serde(flatten)]
    pub action: Action,

    #[serde(flatten)]
    pub resource: Option<Resource>,

    #[serde(rename = "Condition", skip_serializing_if = "Option::is_none")]
    pub condition: Option<Conditions>,
}

impl Default for Statement {
    fn default() -> Self {
        Self {
            sid: Default::default(),
            effect: Default::default(),
            principal: Default::default(),
            action: Action::actions(&[] as &[&str]),
            resource: Default::default(),
            condition: Default::default(),
        }
    }
}

impl Statement {
    pub fn allow(action: Action, resource: Resource) -> Self {
        Self {
            effect: Effect::Allow,
            action,
            resource: Some(resource),
            ..Default::default()
        }
    }

    pub fn deny() -> Self {
        Self {
            effect: Effect::Deny,
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyDocument {
    #[serde(rename = "Id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[serde(rename = "Statement")]
    pub statement: Vec<Statement>,

    /// Enable round-trip forward compatibility, by capturing all extra
    /// attributes into a Map.
    #[serde(flatten)]
    pub _extra: HashMap<String, serde_json::Value>,
}

impl Default for PolicyDocument {
    fn default() -> Self {
        Self {
            id: Default::default(),
            version: None,
            statement: Default::default(),
            _extra: HashMap::new(),
        }
    }
}

impl PolicyDocument {
    pub const V2008_10_17: &'static str = "2008-10-17";
    pub const V2012_10_17: &'static str = "2012-10-17";

    pub fn new(statements: Vec<Statement>) -> Self {
        Self {
            version: Some(Self::V2012_10_17.to_string()),
            statement: statements,
            ..Default::default()
        }
    }

    pub fn from(version: String, statements: Vec<Statement>) -> Self {
        Self {
            version: Some(version),
            statement: statements,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn effect_allow() -> anyhow::Result<()> {
        let e = Effect::Allow;
        let txt = serde_json::to_string(&e).unwrap();
        assert_eq!(r#""Allow""#, txt);
        assert_eq!(e, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn effect_deny() -> anyhow::Result<()> {
        let e = Effect::Deny;
        let txt = serde_json::to_string(&e).unwrap();
        assert_eq!(r#""Deny""#, txt);
        assert_eq!(e, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn effect_default() -> anyhow::Result<()> {
        assert_eq!(Effect::Allow, Effect::default());
        Ok(())
    }

    #[test]
    fn prinicpal_all() -> anyhow::Result<()> {
        let p = PrincipalKind::All;
        let txt = serde_json::to_string(&p).unwrap();
        assert_eq!(r#""*""#, txt);
        assert_eq!(p, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn prinicpal_aws() -> anyhow::Result<()> {
        let p = PrincipalKind::aws(&["x"]);
        let txt = serde_json::to_string(&p).unwrap();
        assert_eq!(r#"{"AWS":["x"]}"#, txt);
        assert_eq!(p, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn prinicpal_service() -> anyhow::Result<()> {
        let p = PrincipalKind::service(&["x"]);
        let txt = serde_json::to_string(&p).unwrap();
        assert_eq!(r#"{"Service":["x"]}"#, txt);
        assert_eq!(p, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn prinicpal_federated() -> anyhow::Result<()> {
        let p = PrincipalKind::federated(&["x"]);
        let txt = serde_json::to_string(&p).unwrap();
        assert_eq!(r#"{"Federated":["x"]}"#, txt);
        assert_eq!(p, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn prinicpal_canonical_user() -> anyhow::Result<()> {
        let p = PrincipalKind::canonical_user(&["x"]);
        let txt = serde_json::to_string(&p).unwrap();
        assert_eq!(r#"{"CanonicalUser":["x"]}"#, txt);
        assert_eq!(p, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn principal_block() -> anyhow::Result<()> {
        let s = Statement {
            principal: Some(Principal::Principal {
                principal: PrincipalKind::All,
            }),
            ..Default::default()
        };
        let txt = serde_json::to_string(&s).unwrap();
        //assert_eq!(r#"{"Principal":"*"}"#, txt);
        assert_eq!(s, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn not_principal_block() -> anyhow::Result<()> {
        let s = Statement {
            principal: Some(Principal::NotPrincipal {
                principal: PrincipalKind::All,
            }),
            ..Default::default()
        };
        let txt = serde_json::to_string(&s).unwrap();
        //assert_eq!(r#"{"NotPrincipal":"*"}"#, txt);
        assert_eq!(s, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn action_one() -> anyhow::Result<()> {
        let a = Action::action("*");
        let txt = serde_json::to_string(&a).unwrap();
        assert_eq!(r#"{"Action":"*"}"#, txt);
        assert_eq!(a, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn action_many() -> anyhow::Result<()> {
        let a = Action::actions(&["a"]);
        let txt = serde_json::to_string(&a).unwrap();
        assert_eq!(r#"{"Action":["a"]}"#, txt,);
        assert_eq!(a, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn action_block() -> anyhow::Result<()> {
        let s = Statement {
            action: Action::action("*"),
            ..Default::default()
        };
        let txt = serde_json::to_string(&s).unwrap();
        assert_eq!(r#"{"Effect":"Allow","Action":"*"}"#, txt.as_str());
        assert_eq!(s, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn not_action_block() -> anyhow::Result<()> {
        let s = Statement {
            action: Action::not_action("*"),
            ..Default::default()
        };
        let txt = serde_json::to_string(&s).unwrap();
        assert_eq!(r#"{"Effect":"Allow","NotAction":"*"}"#, txt.as_str());
        assert_eq!(s, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn resource_one() -> anyhow::Result<()> {
        let a = Resource::resource("*");
        let txt = serde_json::to_string(&a).unwrap();
        assert_eq!(r#"{"Resource":"*"}"#, txt);
        assert_eq!(a, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn resource_many() -> anyhow::Result<()> {
        let a = Resource::resources(&["a"]);
        let txt = serde_json::to_string(&a).unwrap();
        assert_eq!(r#"{"Resource":["a"]}"#, txt,);
        assert_eq!(a, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn resource_block() -> anyhow::Result<()> {
        let s = Statement {
            resource: Some(Resource::resource("*")),
            ..Default::default()
        };
        let txt = serde_json::to_string(&s).unwrap();
        assert_eq!(
            r#"{"Effect":"Allow","Action":[],"Resource":"*"}"#,
            txt.as_str()
        );
        assert_eq!(s, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn not_resource_block() -> anyhow::Result<()> {
        let s = Statement {
            resource: Some(Resource::not_resource("*")),
            ..Default::default()
        };
        let txt = serde_json::to_string(&s).unwrap();
        assert_eq!(
            r#"{"Effect":"Allow","Action":[],"NotResource":"*"}"#,
            txt.as_str()
        );
        assert_eq!(s, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn condition_one() -> anyhow::Result<()> {
        let mut c = Conditions::new();
        let mut a = ConditionMap::new();
        a.insert(
            "key".to_string(),
            ConditionValues::One("value".to_string().into()),
        );
        c.insert("StringEquals".to_string(), a);
        let txt = serde_json::to_string(&c).unwrap();
        assert_eq!(r#"{"StringEquals":{"key":"value"}}"#, txt);
        assert_eq!(c, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn condition_many() -> anyhow::Result<()> {
        let mut c = Conditions::new();
        let mut a = ConditionMap::new();
        a.insert(
            "key".to_string(),
            ConditionValues::Many(vec!["value".to_string().into()]),
        );
        c.insert("StringEquals".to_string(), a);
        let txt = serde_json::to_string(&c).unwrap();
        assert_eq!(r#"{"StringEquals":{"key":["value"]}}"#, txt);
        assert_eq!(c, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn statement() -> anyhow::Result<()> {
        let mut c = Conditions::new();
        let mut a = ConditionMap::new();
        a.insert(
            "key".to_string(),
            ConditionValues::Many(vec!["value".to_string().into()]),
        );
        c.insert("StringEquals".to_string(), a);
        let mut s = Statement::default();
        s.action = Action::action("x");
        s.resource = Some(Resource::resource("*"));
        s.condition = Some(c);
        s.principal = Some(Principal::aws(&["p"]));
        let txt = serde_json::to_string(&s).unwrap();
        //assert_eq!(r#"{"StringEquals":{"key":["value"]}}"#, txt);
        assert_eq!(s, serde_json::from_str(txt.as_str()).unwrap());
        Ok(())
    }

    #[test]
    fn assume_role_document() -> anyhow::Result<()> {
        let raw_input = r#"
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "arn:aws:iam::531625857322:oidc-provider/oidc.eks.eu-central-1.amazonaws.com/id/F9C16C0A32FC4A6972962AA8025418C7"
                        },
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "StringEquals": {
                            "oidc.eks.eu-central-1.amazonaws.com/id/F9C16C0A32FC4A6972962AA8025418C7:sub": "system:serviceaccount:kube-system:cluster-autoscaler"
                            }
                        }
                        }
                    ]
                    }"#;
        let input: Value = serde_json::from_str(raw_input)?;
        let document: PolicyDocument = serde_json::from_value(input.clone())?;
        let rendered = serde_json::to_value(&document)?;
        //assert_eq!(r#"{"StringEquals":{"key":["value"]}}"#, txt);
        assert_eq!(input, rendered);
        //assert_eq!(document, PolicyDocument::default());
        Ok(())
    }

    /*
        {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "Federated": "arn:aws:iam::531625857322:oidc-provider/oidc.eks.eu-central-1.amazonaws.com/id/F9C16C0A32FC4A6972962AA8025418C7"
          },
          "Action": "sts:AssumeRoleWithWebIdentity",
          "Condition": {
            "StringEquals": {
              "oidc.eks.eu-central-1.amazonaws.com/id/F9C16C0A32FC4A6972962AA8025418C7:sub": "system:serviceaccount:kube-system:cluster-autoscaler"
            }
          }
        }
      ]
    }
        */
}
