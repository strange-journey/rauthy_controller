pub mod controller;
pub mod rauthy;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Kubernetes error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Rauthy API error: {0}")]
    RauthyApiError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Finalizer Error: {0}")]
    // NB: awkward type because finalizer::Error embeds the reconciler error (which is this)
    // so boxing this error to break cycles
    FinalizerError(#[source] Box<kube::runtime::finalizer::Error<Error>>),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub use crate::controller::*;