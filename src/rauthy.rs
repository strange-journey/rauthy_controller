use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

static AUTHORIZATION: &str = "Authorization";

/// Matches the `NewClientRequest`` schema in the Rauthy API.
#[derive(Debug, Serialize)]
pub struct NewClientRequest {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub confidential: bool,
    pub redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
}

/// Matches the `UpdateClientRequest`` schema in the Rauthy API.
#[derive(Debug, Serialize)]
pub struct UpdateClientRequest {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub confidential: bool,
    pub redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_origins: Option<Vec<String>>,
    pub enabled: bool,
    pub flows_enabled: Vec<String>,
    pub access_token_alg: String,
    pub id_token_alg: String,
    pub auth_code_lifetime: i32,
    pub access_token_lifetime: i32,
    pub scopes: Vec<String>,
    pub default_scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenges: Option<Vec<String>>,
    pub force_mfa: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restrict_group_prefix: Option<String>,
    pub scim: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ClientSecretRequest {
    pub cache_current_hours: Option<u32>,
}

/// Matches the `ClientSecretResponse`` schema in the Rauthy API.
#[derive(Debug, Deserialize)]
pub struct ClientSecretResponse {
    pub id: String,
    pub confidential: bool,
    /// Present when a new secret has just been generated.
    pub secret: Option<String>,
}

#[derive(Clone)]
pub struct RauthyClient {
    client: Client,
    base_url: String,
    api_key: String,
}

impl RauthyClient {
    pub fn new(base_url: String, api_key: String) -> Result<Self> {
        let client = Client::builder()
            .build()
            .map_err(|e| Error::RauthyApiError {
                status: None,
                message: format!("Failed to build HTTP client: {e}"),
            })?;

        Ok(Self {
            client,
            base_url,
            api_key,
        })
    }

    fn authz_header(&self) -> String {
        format!("API-Key {}", self.api_key)
    }

    pub async fn client_exists(&self, id: &str) -> Result<bool> {
        let url = format!("{}/auth/v1/clients/{id}", self.base_url);
        let res = self
            .client
            .get(&url)
            .header(AUTHORIZATION, self.authz_header())
            .send()
            .await
            .map_err(|e| Error::RauthyApiError {
                status: None,
                message: format!("GET /clients/{id}: {e}"),
            })?;

        match res.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            status => {
                let body = res.text().await.unwrap_or_default();
                Err(Error::RauthyApiError {
                    status: Some(status.as_u16()),
                    message: format!("GET /clients/{id} returned {status}: {body}"),
                })
            }
        }
    }

    pub async fn create_client(&self, req: &NewClientRequest) -> Result<()> {
        let url = format!("{}/auth/v1/clients", self.base_url);
        let res = self
            .client
            .post(&url)
            .header(AUTHORIZATION, self.authz_header())
            .json(req)
            .send()
            .await
            .map_err(|e| Error::RauthyApiError {
                status: None,
                message: format!("POST /clients: {e}"),
            })?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(Error::RauthyApiError {
                status: Some(status.as_u16()),
                message: format!("POST /clients returned {status}: {body}"),
            });
        }
        Ok(())
    }

    pub async fn update_client(&self, req: &UpdateClientRequest) -> Result<()> {
        let url = format!("{}/auth/v1/clients/{}", self.base_url, req.id);
        let res = self
            .client
            .put(&url)
            .header(AUTHORIZATION, self.authz_header())
            .json(req)
            .send()
            .await
            .map_err(|e| Error::RauthyApiError {
                status: None,
                message: format!("PUT /clients/{}: {e}", req.id),
            })?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(Error::RauthyApiError {
                status: Some(status.as_u16()),
                message: format!("PUT /clients/{} returned {status}: {body}", req.id),
            });
        }
        Ok(())
    }

    pub async fn delete_client(&self, id: &str) -> Result<()> {
        let url = format!("{}/auth/v1/clients/{id}", self.base_url);
        let res = self
            .client
            .delete(&url)
            .header(AUTHORIZATION, self.authz_header())
            .send()
            .await
            .map_err(|e| Error::RauthyApiError {
                status: None,
                message: format!("DELETE /clients/{id}: {e}"),
            })?;

        match res.status() {
            StatusCode::OK | StatusCode::NO_CONTENT | StatusCode::NOT_FOUND => Ok(()),
            status => {
                let body = res.text().await.unwrap_or_default();
                Err(Error::RauthyApiError {
                    status: Some(status.as_u16()),
                    message: format!("DELETE /clients/{id} returned {status}: {body}"),
                })
            }
        }
    }

    pub async fn get_client_secret(&self, id: &str) -> Result<String> {
        let url = format!("{}/auth/v1/clients/{id}/secret", self.base_url);
        let res = self
            .client
            .post(&url)
            .header(AUTHORIZATION, self.authz_header())
            .send()
            .await
            .map_err(|e| Error::RauthyApiError {
                status: None,
                message: format!("POST /clients/{id}/secret: {e}"),
            })?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(Error::RauthyApiError {
                status: Some(status.as_u16()),
                message: format!("POST /clients/{id}/secret returned {status}: {body}"),
            });
        }

        let secret_response: ClientSecretResponse =
            res.json().await.map_err(|e| Error::RauthyApiError {
                status: None,
                message: format!("failed to parse secret response: {e}"),
            })?;

        secret_response.secret.ok_or_else(|| Error::RauthyApiError {
            status: None,
            message: format!("The API response did not contain the secret for client {id}"),
        })
    }

    pub async fn generate_client_secret(
        &self,
        id: &str,
        cache_current_hours: Option<u32>,
    ) -> Result<String> {
        let url = format!("{}/auth/v1/clients/{id}/secret", self.base_url);
        let req = ClientSecretRequest {
            cache_current_hours,
        };
        let res = self
            .client
            .put(&url)
            .header(AUTHORIZATION, self.authz_header())
            .json(&req)
            .send()
            .await
            .map_err(|e| Error::RauthyApiError {
                status: None,
                message: format!("PUT /clients/{id}/secret: {e}"),
            })?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(Error::RauthyApiError {
                status: Some(status.as_u16()),
                message: format!("PUT /clients/{id}/secret returned {status}: {body}"),
            });
        }

        let secret_response: ClientSecretResponse =
            res.json().await.map_err(|e| Error::RauthyApiError {
                status: None,
                message: format!("failed to parse secret response: {e}"),
            })?;

        secret_response.secret.ok_or_else(|| Error::RauthyApiError {
            status: None,
            message: format!("The API response did not contain the secret for client {id}"),
        })
    }
}
