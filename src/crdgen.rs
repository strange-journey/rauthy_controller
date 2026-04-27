use kube::CustomResourceExt;
use rauthy_controller::controller;

fn main() {
    let mut crd = controller::OIDCClient::crd();
    crd.metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert("helm.sh/resource-policy".to_string(), "keep".to_string());

    print!("{}", serde_yaml::to_string(&crd).unwrap());
}
