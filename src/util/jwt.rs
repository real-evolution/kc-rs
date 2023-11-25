use std::{fmt, str::FromStr};

use jsonwebtoken::{
    self as jwt,
    errors::{Error as JwtError, ErrorKind as JwtErrorKind},
    Algorithm,
};

const REQUIRED_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "jti",
    "preferred_username",
    "realm_access",
    "resource_access",
];

#[derive(Debug, Clone)]
pub struct JwtDecoder {
    keys: Vec<Jwk>,
}

#[derive(Clone)]
struct Jwk {
    kid: Option<String>,
    key: jwt::DecodingKey,
    vld: jwt::Validation,
}

impl JwtDecoder {
    #[inline]
    pub async fn new(client: &crate::Client) -> crate::Result<Self> {
        let certs = client.certs().await?;
        let keys = certs
            .keys
            .into_iter()
            .filter_map(|jwk| Jwk::new(jwk, client.urls().issuer.as_ref()).ok())
            .collect();

        Ok(Self { keys })
    }

    #[inline]
    pub fn decode(
        &self,
        token: impl AsRef<str>,
    ) -> crate::Result<jwt::TokenData<crate::Claims>> {
        self.get_key_for(token.as_ref())?.decode(token)
    }

    fn get_key_for(&self, token: &str) -> crate::Result<&Jwk> {
        let header = jwt::decode_header(token)?;

        let key = if self.keys.len() == 1 {
            &self.keys[0]
        } else {
            self.keys
                .iter()
                .find(|key| key.kid == header.kid)
                .ok_or_else(|| JwtError::from(JwtErrorKind::InvalidToken))?
        };

        Ok(key)
    }
}

impl Jwk {
    #[inline]
    fn new(jwk: jwt::jwk::Jwk, issuer: &str) -> crate::Result<Self> {
        let alg_name = jwk.common.key_algorithm.unwrap().to_string();

        let alg = Algorithm::from_str(alg_name.as_str())?;
        let key = jwt::DecodingKey::from_jwk(&jwk)?;
        let kid = jwk.common.key_id;

        let mut vld = jwt::Validation::new(alg);
        vld.set_required_spec_claims(REQUIRED_CLAIMS);
        vld.set_issuer(&[issuer]);

        Ok(Self { kid, key, vld })
    }

    #[inline]
    fn decode(&self, token: impl AsRef<str>) -> crate::Result<crate::Token> {
        let token = jwt::decode(token.as_ref(), &self.key, &self.vld)?;

        Ok(token)
    }
}

impl fmt::Debug for Jwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtDecoder")
            .field("kid", &self.kid)
            .field("key", &"[redacted]")
            .field("vld", &self.vld)
            .finish()
    }
}
