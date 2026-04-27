use std::sync::Arc;

use kube::Client;
use rauthy_controller::{Error, Result, controller, rauthy::RauthyClient};

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| Error::ConfigError(format!("missing required env var: {name}")))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    // RAUTHY_URL:     base URL of the Rauthy instance, e.g. https://rauthy.example.com
    // RAUTHY_API_KEY: API-Key credential in the format <name>$<secret>
    let rauthy_url = required_env("RAUTHY_URL")?;
    let rauthy_api_key = required_env("RAUTHY_API_KEY")?;

    // WATCH_NAMESPACE: optional comma-separated list of namespaces to watch.
    // If unset or empty, the controller watches all namespaces.
    let watch_namespaces = std::env::var("WATCH_NAMESPACE")
        .map(|s| {
            s.split(',')
                .map(|ns| ns.trim().to_string())
                .filter(|ns| !ns.is_empty())
                .collect()
        })
        .unwrap_or_else(|_| Vec::new());

    let client = Client::try_default().await?;
    let rauthy = RauthyClient::new(rauthy_url, rauthy_api_key)?;
    let ctx = Arc::new(controller::Context { client, rauthy });

    controller::run(ctx, watch_namespaces).await;

    Ok(())
}
