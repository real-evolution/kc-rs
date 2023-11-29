mod config;
mod error;
mod jwt;
mod token;

#[cfg(feature = "middleware")]
pub mod middleware;

use std::sync::Arc;

pub use config::Config;
pub use error::{Error, Result};
pub use jwt::JwtDecoder;
pub use token::{Claims, Token, TokenContainer};

#[derive(Debug)]
pub struct ReCloak {
    client: reqwest::Client,
    decoder: JwtDecoder,
    config: Config,
    urls: config::ServerEndpoints,
}

impl ReCloak {
    pub async fn new(config: Config) -> Result<Arc<Self>> {
        tracing::debug!(
            agent = %config.http.user_agent,
            auth_server_url = %config.http.auth_server_url,
            realm = %config.client.realm,
            client_id = %config.client.id,
            "creating keycloak client",
        );

        let client = reqwest::ClientBuilder::new()
            .user_agent(&config.http.user_agent)
            .build()?;

        let urls = config.urls()?;
        let jwks = Self::get_certs(&client, urls.jwks.clone()).await?;
        let decoder = JwtDecoder::new(jwks, &config);

        Ok(Arc::new(Self {
            config,
            client,
            decoder,
            urls,
        }))
    }

    pub async fn login_client(
        &self,
        creds: ClientGrant<'_>,
    ) -> Result<TokenContainer> {
        self.client
            .post(self.urls.token.clone())
            .form(&creds)
            .send()
            .await?
            .json::<TokenContainer>()
            .await
            .map_err(Into::into)
    }

    #[inline]
    pub fn decode_token(
        &self,
        token: impl AsRef<str>,
    ) -> crate::Result<crate::Token> {
        self.decoder.decode(token)
    }

    #[inline]
    pub async fn jwks(&self) -> Result<jsonwebtoken::jwk::JwkSet> {
        Self::get_certs(&self.client, self.urls.jwks.clone()).await
    }

    #[inline]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    async fn get_certs(
        client: &reqwest::Client,
        url: url::Url,
    ) -> Result<jsonwebtoken::jwk::JwkSet> {
        tracing::debug!(%url, "fetching keycloak certs");

        client
            .get(url)
            .send()
            .await?
            .json()
            .await
            .map_err(Into::into)
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(tag = "grant_type")]
pub enum ClientGrant<'a> {
    #[serde(rename = "client_credentials")]
    ClientCredentials {
        #[serde(rename = "client_id")]
        id: &'a str,

        #[serde(rename = "client_secret")]
        secret: &'a str,
    },
}
