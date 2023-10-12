use crate::{util::UrlBuilder, TokenContainer};

pub type HttpClient = reqwest::Client;

#[derive(Debug)]
pub struct Client {
    inner: HttpClient,
    urls: ServerEndpoints,
}

impl Client {
    pub fn new(base: url::Url, realm: impl AsRef<str>) -> crate::Result<Self> {
        const USER_AGENT: &str =
            concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

        tracing::debug!(
            agent = %USER_AGENT,
            auth_server_url = %base,
            realm = %realm.as_ref(),
            "creating keycloak client",
        );

        let urls = ServerEndpoints::new(base, realm.as_ref())?;
        let inner = reqwest::ClientBuilder::new()
            .user_agent(USER_AGENT)
            .build()?;

        Ok(Self { inner, urls })
    }

    #[inline]
    pub async fn login_client(
        &self,
        creds: ClientGrant<'_>,
    ) -> crate::Result<TokenContainer> {
        self.inner
            .post(self.urls.token.clone())
            .form(&creds)
            .send()
            .await?
            .json::<TokenContainer>()
            .await
            .map_err(Into::into)
    }

    #[inline]
    pub async fn certs(&self) -> crate::Result<jsonwebtoken::jwk::JwkSet> {
        tracing::debug!(
            url = %self.urls.jwks,
            "fetching keycloak certs",
        );

        self.inner
            .get(self.urls.jwks.clone())
            .send()
            .await?
            .json()
            .await
            .map_err(Into::into)
    }

    #[inline]
    pub const fn urls(&self) -> &ServerEndpoints {
        &self.urls
    }
}

#[derive(Debug, Clone)]
pub struct ServerEndpoints {
    pub issuer: url::Url,
    pub auth: url::Url,
    pub token: url::Url,
    pub introspect: url::Url,
    pub jwks: url::Url,
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

impl ServerEndpoints {
    fn new(base: url::Url, realm: &str) -> crate::Result<Self> {
        let issuer = UrlBuilder::new(base)?.push("realms").push(realm);
        let oidc = issuer.clone().push("protocol").push("openid-connect");

        Ok(Self {
            issuer: issuer.take(),
            auth: oidc.clone().push("auth").take(),
            token: oidc.clone().push("token").take(),
            introspect: oidc.clone().push("introspect").take(),
            jwks: oidc.clone().push("certs").take(),
        })
    }
}
