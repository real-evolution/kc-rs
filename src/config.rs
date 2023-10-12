use crate::ClientGrant;

#[derive(Debug, serde::Deserialize)]
pub struct Config {
    pub realm: String,
    pub client_id: String,
    pub client_secret: ClientSecret,
    #[serde(rename = "auth_server_url")]
    pub auth_server: url::Url,
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
pub enum ClientSecret {
    Basic(String),
}

impl Config {
    pub fn token_grant(&self) -> ClientGrant<'_> {
        match self.client_secret {
            | ClientSecret::Basic(ref secret) => {
                ClientGrant::ClientCredentials {
                    id: self.client_id.as_str(),
                    secret,
                }
            }
        }
    }
}
