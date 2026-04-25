use kube::CustomResourceExt;
use rauthy_controller::controller;
fn main() {
    print!("{}", serde_yaml::to_string(&controller::OIDCClient::crd()).unwrap())
}