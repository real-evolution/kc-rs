mod client;
mod config;
mod error;
mod token;
mod util;

#[cfg(feature = "middleware")]
pub mod middleware;

use std::sync::Arc;

pub use client::{Client, ClientGrant};
pub use config::Config;
pub use error::{Error, Result};
pub use token::{Claims, Token, TokenContainer};

#[derive(Debug)]
pub struct ReCloak {
    config: config::Config,
    client: client::Client,
    decoder: util::JwtDecoder,
}

impl ReCloak {
    pub async fn new(config: Config) -> Result<Arc<Self>> {
        let client = Client::new(config.auth_server.clone(), &config.realm)?;
        let decoder = util::JwtDecoder::new(&client).await?;

        Ok(Arc::new(Self {
            config,
            client,
            decoder,
        }))
    }

    pub async fn login_client(&self) -> crate::Result<TokenContainer> {
        let grant = self.config.token_grant();
        let token = self.client.login_client(grant).await?;

        Ok(token)
    }

    #[inline]
    pub fn decode_token(
        &self,
        token: impl AsRef<str>,
    ) -> crate::Result<crate::Token> {
        self.decoder.decode(token)
    }

    #[inline]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    #[inline]
    pub const fn client(&self) -> &Client {
        &self.client
    }
}
