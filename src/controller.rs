use std::{collections::BTreeMap, sync::Arc, time::Duration};
use futures::StreamExt;
use k8s_openapi::{ByteString, api::core::v1::Secret};
use serde::{Serialize, Deserialize};
use kube::{
    CustomResource, Resource, api::{Api, DeleteParams, ListParams, ObjectMeta, PatchParams, ResourceExt}, client::Client, runtime::{
        controller::{Action, Controller},
        finalizer::{Event as Finalizer, finalizer}, watcher,
    }
};
use schemars::JsonSchema;
use tracing::*;

use crate::{
    rauthy::RauthyClient,
    Result, Error,
};

pub static OIDC_CLIENT_FINALIZER: &str = "rauthy.io/oidcclient-finalizer";
pub static FIELD_MANAGER: &str = "rauthy-controller";
pub static APPLICATION_NAME: &str = "rauthy-controller";

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(kind = "OIDCClient", group = "rauthy.io", version = "v1alpha1", namespaced)]
pub struct OIDCClientSpec {
    /// The Rauthy client ID. Changing this after creation will create a new client.
    pub client_id: String,

    /// Whether this is a confidential client (secret required).
    pub confidential: bool,

    /// Allowed redirect URIs.
    pub redirect_uris: Vec<String>,

    /// Allowed post-logout redirect URIs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,

    /// Human-readable display name for the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// URI of the client application (shown in the consent screen).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,

    /// Contact e-mail addresses for this client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,

    /// Whether this client is currently enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Require MFA for all logins via this client.
    #[serde(default)]
    pub force_mfa: bool,

    /// Restrict logins to users whose primary group starts with this prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restrict_group_prefix: Option<String>,

    /// Allowed CORS origins (e.g. `["https://app.example.com"]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_origins: Option<Vec<String>>,

    /// Enabled OAuth2/OIDC grant flows.
    /// Valid values: `authorization_code`, `client_credentials`, `refresh_token`,
    /// `urn:ietf:params:oauth:grant-type:device_code`.
    #[serde(default = "default_flows")]
    pub flows_enabled: Vec<String>,

    /// Algorithm used to sign access tokens (`RS256`, `RS384`, `RS512`, `EdDSA`).
    #[serde(default = "default_alg")]
    pub access_token_alg: String,

    /// Algorithm used to sign ID tokens (`RS256`, `RS384`, `RS512`, `EdDSA`).
    #[serde(default = "default_alg")]
    pub id_token_alg: String,

    /// Authorization code lifetime in seconds (10–300).
    #[serde(default = "default_auth_code_lifetime")]
    pub auth_code_lifetime: i32,

    /// Access token lifetime in seconds (10–86400).
    #[serde(default = "default_access_token_lifetime")]
    pub access_token_lifetime: i32,

    /// Scopes this client is allowed to request.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,

    /// Scopes included in every token without explicit request.
    #[serde(default = "default_default_scopes")]
    pub default_scopes: Vec<String>,

    /// Allowed PKCE challenge methods (e.g. `["S256"]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenges: Option<Vec<String>>,

    /// OIDC backchannel logout URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,

    /// If `confidential` is true, the controller will create and maintain a
    /// Kubernetes Secret with this name in the same namespace.
    /// Defaults to `{client_id}-oidc-secret` when not set.
    /// The Secret will contain `client_id` and `client_secret` keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,

    /// Number of hours for which the existing client secret should be cached by the controller.
    /// This optionally allows graceful secret rotation and keeps the current Rauthy secret cached in-memory.
    /// A value of 1-24 hours is allowwed here.
    /// TODO: validate that the value is within the allowed range (https://kube.rs/controllers/admission/)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_cache_current_hours: Option<u32>,
}

fn default_true() -> bool {
    true
}

fn default_flows() -> Vec<String> {
    vec![
        "authorization_code".to_string(),
        "refresh_token".to_string(),
    ]
}

fn default_alg() -> String {
    "EdDSA".to_string()
}

fn default_auth_code_lifetime() -> i32 {
    60
}

fn default_access_token_lifetime() -> i32 {
    1800
}

fn default_scopes() -> Vec<String> {
    vec![
        "email".to_string(),
        "openid".to_string(),
        "profile".to_string(),
        "groups".to_string(),
    ]
}

fn default_default_scopes() -> Vec<String> {
    vec!["openid".to_string()]
}

impl OIDCClientSpec {
    pub fn resolve_secret_name(&self) -> Option<String> {
        self.confidential.then(|| {
            self.secret_name
                .clone()
                .unwrap_or_else(|| format!("{}-oidc-secret", self.client_id))
        })
    }
    pub fn to_rauthy_new_client_request(&self) -> crate::rauthy::NewClientRequest {
        crate::rauthy::NewClientRequest {
            id: self.client_id.clone(), 
            name: self.name.clone(), 
            confidential: self.confidential, 
            redirect_uris: self.redirect_uris.clone(), 
            post_logout_redirect_uris: self.post_logout_redirect_uris.clone() 
        }
    }
    
    pub fn to_rauthy_update_client_request(&self) -> crate::rauthy::UpdateClientRequest {
        crate::rauthy::UpdateClientRequest {
            id: self.client_id.clone(),
            name: self.name.clone(),
            confidential: self.confidential,
            redirect_uris: self.redirect_uris.clone(),
            post_logout_redirect_uris: self.post_logout_redirect_uris.clone(),
            allowed_origins: self.allowed_origins.clone(),
            enabled: self.enabled,
            flows_enabled: self.flows_enabled.clone(),
            access_token_alg: self.access_token_alg.clone(),
            id_token_alg: self.id_token_alg.clone(),
            auth_code_lifetime: self.auth_code_lifetime,
            access_token_lifetime: self.access_token_lifetime,
            scopes: self.scopes.clone(),
            default_scopes: self.default_scopes.clone(),
            challenges: self.challenges.clone(),
            force_mfa: self.force_mfa,
            client_uri: self.client_uri.clone(),
            contacts: self.contacts.clone(),
            backchannel_logout_uri: self.backchannel_logout_uri.clone(),
            restrict_group_prefix: self.restrict_group_prefix.clone(),
            scim: None,
        }
    }
}

#[derive(Clone)]
pub struct Context {
    pub client: Client,
    pub rauthy: RauthyClient,
}

fn error_policy(_oidc_client: Arc<OIDCClient>, error: &Error, _ctx: Arc<Context>) -> Action {
    warn!("reconcile failed: {:?}", error);
    Action::requeue(Duration::from_mins(5))
}

pub async fn run(ctx: Arc<Context>) {
    let oidc_clients = Api::<OIDCClient>::all(ctx.client.clone());
    let secrets = Api::<Secret>::all(ctx.client.clone());
    if let Err(e) = oidc_clients.list(&ListParams::default().limit(1)).await {
        error!("CRD is not queryable; {e:?}. Is the CRD installed?");
        info!("Installation: cargo run --bin crdgen | kubectl apply -f -");
        std::process::exit(1);
    }

    Controller::new(oidc_clients, watcher::Config::default())
        .owns(secrets, watcher::Config::default()
            .labels(&format!("app.kubernetes.io/managed-by={APPLICATION_NAME}")))
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|_| futures::future::ready(()))
        .await;
}

async fn reconcile(oidc_client: Arc<OIDCClient>, ctx: Arc<Context>) -> Result<Action> {
    let ns = oidc_client.namespace().unwrap();
    let oidc_clients: Api<OIDCClient> = Api::namespaced(ctx.client.clone(), &ns);

    finalizer(&oidc_clients, OIDC_CLIENT_FINALIZER, oidc_client, |event| async {
        match event {
            Finalizer::Apply(oidc_client) => oidc_client.reconcile(ctx.clone()).await,
            Finalizer::Cleanup(oidc_client) => oidc_client.cleanup(ctx.clone()).await,
        }
    })
    .await
    .map_err(|e| Error::FinalizerError(Box::new(e)))
}

impl OIDCClient {
    async fn reconcile(&self, ctx: Arc<Context>) -> Result<Action> {
        let ns = self.namespace().unwrap();
        let _oidc_clients: Api<OIDCClient> = Api::namespaced(ctx.client.clone(), &ns);
        let client_id = &self.spec.client_id;

        let is_new = !ctx.rauthy.client_exists(client_id).await?;
        (if is_new {
            // if this is a new client, create with API and then update rest of fields
            info!(client_id = %client_id, "client not found in Rauthy, creating");
            ctx.rauthy.create_client(&self.spec.to_rauthy_new_client_request())
            .await
            .and(
                ctx.rauthy.update_client(&self.spec.to_rauthy_update_client_request())
                .await
            )
        }
        else {
            info!(client_id = %client_id, "client exists in Rauthy, updating");
            ctx.rauthy.update_client(&self.spec.to_rauthy_update_client_request())
            .await
        }).inspect_err(|_| {
            // add error message to status here
        })?;

        if self.spec.confidential {
            // call ensure_secret here..
            self.ensure_secret(&ctx, is_new)
            .await
            .inspect_err(|_| {
                // add error message to status here
            })?;
        }

        // set status to success here

        // If no events were received, check back every 5 minutes
        Ok(Action::requeue(Duration::from_mins(5)))
    }

    async fn ensure_secret(&self, ctx: &Context, is_new_client: bool) -> Result<()> {
        let ns = self.namespace().unwrap();
        let Some(secret_name) = self.spec.resolve_secret_name() else { return Ok(()) };
        let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), &ns);
        
        let client_id = &self.spec.client_id;
        let client_id_bytes = ByteString(client_id.clone().into_bytes());

        let client_secret_bytes = if let Some(current_secret) = secrets.get_opt(&secret_name).await? {
            let client_secret_bytes = ByteString(ctx.rauthy.get_client_secret(client_id).await?.into_bytes());

            if current_secret.data.is_some_and(|data| {
                data.get("client_id") == Some(&client_id_bytes) 
                && data.get("client_secret") == Some(&client_secret_bytes)
            }) {
                // if Secret exists and matches, no apply is necessary
                return Ok(())
            }
            else {
                // the existing kube Secret does not match the Rauthy client credentials, 
                // so delete it to allow re-creation with correct values.
                // server-side apply will not be able to replace an immutable Secret, even with force.
                info!(client_id = %client_id, secret_name = %secret_name, "existing Secret does not match, deleting");
                secrets.delete(&secret_name, &DeleteParams::default()).await.map_err(Error::KubeError)?;
                client_secret_bytes
            }
        }
        else {
            // the kube Secret does not exist, so generate a new one
            let cache_current_hours = match is_new_client {
                true => None, // for new clients, we should avoid caching the unused initial secret
                false => self.spec.secret_cache_current_hours
            };
            info!(
                client_id = %client_id, 
                secret_name = %secret_name, 
                cache_current_hours = ?cache_current_hours, 
                "generating new client secret"
            );
            ByteString(ctx.rauthy.generate_client_secret(client_id, cache_current_hours).await?.into_bytes())
        };
        
        let oref = self.controller_owner_ref(&()).unwrap();
        let secret = Secret {
            immutable: Some(true),
            metadata: ObjectMeta {
                name: Some(secret_name.clone()),
                namespace: Some(ns),
                owner_references: Some(vec![oref]),
                labels: Some(BTreeMap::from([
                    ("app.kubernetes.io/managed-by".to_string(), APPLICATION_NAME.to_string()),
                ])),
                ..ObjectMeta::default()
            },
            data: Some(BTreeMap::from([
                ("client_id".to_string(), client_id_bytes),
                ("client_secret".to_string(), client_secret_bytes),
            ])),
            ..Secret::default()
        };
        
        secrets.patch(
            &secret_name,
            &PatchParams::apply(FIELD_MANAGER),
            &kube::api::Patch::Apply(secret)
        ).await.map_err(Error::KubeError)?;
        info!(client_id = %client_id, secret_name = %secret_name, "created Kubernetes Secret with client credentials");

        Ok(())
    }

    async fn cleanup(&self, ctx: Arc<Context>) -> Result<Action> {
        let client_id = &self.spec.client_id;
        info!(
            client_id = %client_id,
            resource = %self.name_any(),
            "deleting Rauthy client"
        );
        ctx.rauthy.delete_client(client_id).await?;
        Ok(Action::await_change())
    }
}