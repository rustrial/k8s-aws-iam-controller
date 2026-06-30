use kube::CustomResourceExt;
use rustrial_k8s_aws_iam_apis::{RoleUsagePolicy, TrustPolicyStatement};
use serde_saphyr;

pub fn main() {
    println!("---");
    println!(
        "{}",
        serde_saphyr::to_string(&TrustPolicyStatement::crd()).unwrap()
    );
    println!("---");
    println!(
        "{}",
        serde_saphyr::to_string(&RoleUsagePolicy::crd()).unwrap()
    );
}
