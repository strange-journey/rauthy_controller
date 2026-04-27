pub mod controller;
pub mod rauthy;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use schemars::json_schema;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Kubernetes error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Rauthy API error: {message}")]
    RauthyApiError {
        status: Option<u16>,
        message: String,
    },

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Finalizer Error: {0}")]
    // NB: awkward type because finalizer::Error embeds the reconciler error (which is this)
    // so boxing this error to break cycles
    FinalizerError(#[source] Box<kube::runtime::finalizer::Error<Error>>),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub fn conditions(_: &mut schemars::generate::SchemaGenerator) -> schemars::Schema {
    json_schema!({
        "type": "array",
        "x-kubernetes-list-type": "map",
        "x-kubernetes-list-map-keys": ["type"],
        "items": {
            "type": "object",
            "properties": {
                "lastTransitionTime": { "format": "date-time", "type": "string" },
                "message": { "type": "string" },
                "observedGeneration": { "type": "integer", "format": "int64", "default": 0 },
                "reason": { "type": "string" },
                "status": { "type": "string" },
                "type": { "type": "string" }
            },
            "required": [
                "lastTransitionTime",
                "message",
                "reason",
                "status",
                "type"
            ],
        },
    })
}

pub fn set_condition(
    conditions: &mut Vec<Condition>,
    condition_type: &str,
    status: &str,
    reason: &str,
    message: &str,
    observed_generation: i64,
) {
    let now = Time(jiff::Timestamp::now());

    if let Some(existing) = conditions.iter_mut().find(|c| c.type_ == condition_type) {
        if existing.status != status {
            existing.last_transition_time = now;
        }
        existing.status = status.to_string();
        existing.reason = reason.to_string();
        existing.message = message.to_string();
        existing.observed_generation = Some(observed_generation);
    } else {
        conditions.push(Condition {
            type_: condition_type.to_string(),
            status: status.to_string(),
            reason: reason.to_string(),
            message: message.to_string(),
            last_transition_time: now,
            observed_generation: Some(observed_generation),
        });
    }
}

pub use crate::controller::*;
