use kube::CustomResourceExt;
use rustrial_k8s_aws_iam_apis::{RoleUsagePolicy, TrustPolicyStatement};
use serde_yaml;

pub fn main() {
    println!("---");
    println!(
        "{}",
        serde_yaml::to_string(&TrustPolicyStatement::crd()).unwrap()
    );
    println!("---");
    println!(
        "{}",
        serde_yaml::to_string(&RoleUsagePolicy::crd()).unwrap()
    );
}
