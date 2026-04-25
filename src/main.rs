use std::sync::Arc;

use kube::Client;
use rauthy_controller::{Result, Error, controller, rauthy::RauthyClient};

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
    
    let client = Client::try_default().await?;
    let rauthy = RauthyClient::new(rauthy_url, rauthy_api_key)?;
    let ctx = Arc::new(controller::Context { client, rauthy });

    controller::run(ctx).await;

    Ok(())
}