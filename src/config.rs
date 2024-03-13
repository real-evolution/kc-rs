use serde::Deserialize;
use url::Url;

use crate::Result;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub client: ClientConfig,
    pub token: TokenConfig,
    pub http: HttpConfig,
}

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub id: String,
    pub secret: ClientSecret,
    pub realm: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenConfig {
    pub issuer: Option<Vec<String>>,
    pub audience: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct HttpConfig {
    pub auth_server_url: Url,

    #[serde(default = "default_http_user_agent")]
    pub user_agent: String,

    #[serde(default = "default_http_https_only")]
    pub https_only: bool,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ClientSecret {
    Basic(String),
}

#[derive(Debug, Clone)]
pub struct ServerEndpoints {
    pub issuer: Url,
    pub auth: Url,
    pub token: Url,
    pub introspect: Url,
    pub userinfo: Url,
    pub jwks: Url,
}

impl Config {
    pub(crate) fn urls(&self) -> Result<ServerEndpoints> {
        if self.http.auth_server_url.cannot_be_a_base() {
            return Err(url::ParseError::RelativeUrlWithoutBase)?;
        }

        let mut issuer = self.http.auth_server_url.clone();
        issuer
            .path_segments_mut()
            .unwrap()
            .push("realms")
            .push(&self.client.realm);

        let oidc = build_url(issuer.clone(), "protocol/openid-connect");
        let auth = build_url(oidc.clone(), "auth");
        let token = build_url(oidc.clone(), "token");
        let introspect = build_url(oidc.clone(), "introspect");
        let userinfo = build_url(oidc.clone(), "userinfo");
        let jwks = build_url(oidc.clone(), "certs");

        Ok(ServerEndpoints {
            issuer,
            auth,
            token,
            introspect,
            userinfo,
            jwks,
        })
    }
}

#[inline]
fn build_url(mut base: Url, path: &str) -> Url {
    base.path_segments_mut().unwrap().extend(path.split('/'));
    base
}

#[inline]
fn default_http_user_agent() -> String {
    const USER_AGENT: &str =
        concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

    String::from(USER_AGENT)
}

#[inline]
fn default_http_https_only() -> bool {
    false
}
