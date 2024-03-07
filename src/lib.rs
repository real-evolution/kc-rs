#![feature(impl_trait_in_assoc_type)]

mod config;
mod error;
mod jwt;
mod token;

#[cfg(feature = "middleware")]
pub mod middleware;

use std::{ops::Add, sync::Arc};

use serde_with::DurationSeconds;
use tokio::sync::RwLock;

pub use self::{
    config::{Config, ServerEndpoints},
    error::{Error, Result},
    jwt::JwtDecoder,
    token::{Claims, TokenData},
};

#[derive(Debug)]
pub struct ReCloak {
    client: reqwest::Client,
    decoder: JwtDecoder,
    config: Config,
    urls: ServerEndpoints,
    token: RwLock<Option<TokenResponse>>,
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
            token: Default::default(),
        }))
    }

    #[tracing::instrument(skip(self, creds))]
    pub async fn login_client(
        &self,
        creds: ClientGrant<'_>,
    ) -> Result<TokenResponse> {
        #[derive(serde::Deserialize)]
        struct ErrorDto {
            error: String,
            error_description: Option<String>,
        }

        let resp = self
            .client
            .post(self.urls.token.clone())
            .form(&creds)
            .send()
            .await?;

        if resp.status().is_success() {
            resp.json::<TokenResponse>().await.map_err(From::from)
        } else {
            let err =
                resp.json::<ErrorDto>().await.map_err(crate::Error::from)?;

            Err(crate::Error::Authentication {
                code: err.error,
                description: err.error_description,
            })
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn authenticate(&self) -> Result<arcstr::ArcStr> {
        if let Some(token) = self.token.read().await.as_ref() {
            if !token.is_access_expired() {
                return Ok(token.access_token.clone());
            }

            if let Some(refresh_token) = token.valid_refresh_token() {
                let token_resp = self
                    .login_client(ClientGrant::RefreshToken { refresh_token })
                    .await?;

                let access_token = token_resp.access_token.clone();

                *self.token.write().await = Some(token_resp);

                return Ok(access_token);
            }
        }

        let id = self.config.client.id.as_str();
        let secret = match self.config.client.secret {
            | config::ClientSecret::Basic(ref secret) => secret,
        };

        let token_resp = self
            .login_client(ClientGrant::ClientCredentials { id, secret })
            .await?;
        let access_token = token_resp.access_token.clone();

        *self.token.write().await = Some(token_resp);

        Ok(access_token)
    }

    #[inline]
    #[tracing::instrument(skip(self))]
    pub fn decode_token(&self, token: &str) -> Result<TokenData> {
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

    #[tracing::instrument]
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
            .map_err(From::from)
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

    #[serde(rename = "refresh_token")]
    RefreshToken {
        #[serde(rename = "refresh_token")]
        refresh_token: &'a str,
    },
}

#[derive(Debug, Clone, Copy, serde::Deserialize)]
pub enum TokenType {
    #[serde(alias = "bearer")]
    Bearer,
}

#[serde_with::serde_as]
#[derive(Debug, serde::Deserialize)]
pub struct TokenResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<TokenType>,

    #[serde(rename = "access_token")]
    pub access_token: arcstr::ArcStr,

    #[serde_as(as = "DurationSeconds<i64>")]
    pub expires_in: chrono::Duration,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<arcstr::ArcStr>,

    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub refresh_expires_in: Option<chrono::Duration>,

    #[serde(skip, default = "chrono::Local::now")]
    issued_at: chrono::DateTime<chrono::Local>,
}

impl TokenResponse {
    #[inline]
    fn is_access_expired(&self) -> bool {
        self.issued_at + self.expires_in < chrono::Local::now()
    }

    fn valid_refresh_token(&self) -> Option<&str> {
        match (&self.refresh_token, &self.refresh_expires_in) {
            | (Some(rt), None) => Some(rt.as_str()),
            | (Some(rt), Some(d))
                if self.issued_at.add(*d) > chrono::Local::now() =>
            {
                Some(rt.as_str())
            }
            | _ => None,
        }
    }
}
