use std::{fmt, str::FromStr};

use jsonwebtoken::{
    self as jwt,
    errors::{Error as JwtError, ErrorKind as JwtErrorKind},
    Algorithm,
};

use crate::{Config, Result};

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
    pub fn new(jwks: jwt::jwk::JwkSet, config: &Config) -> Self {
        let keys = jwks
            .keys
            .into_iter()
            .filter_map(|jwk| Jwk::new(jwk, config).ok())
            .collect();

        Self { keys }
    }

    #[inline]
    pub fn decode(
        &self,
        token: &str,
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
    fn new(jwk: jwt::jwk::Jwk, config: &Config) -> Result<Self> {
        let alg_name = jwk.common.key_algorithm.unwrap().to_string();

        let alg = Algorithm::from_str(alg_name.as_str())?;
        let key = jwt::DecodingKey::from_jwk(&jwk)?;
        let kid = jwk.common.key_id;

        let mut vld = jwt::Validation::new(alg);
        vld.set_required_spec_claims(REQUIRED_CLAIMS);

        match config.token.issuer.as_deref() {
            | Some(issuer) => vld.set_issuer(issuer),
            | None => vld.set_issuer(&[config.urls()?.issuer.as_str()]),
        }

        match config.token.audience.as_deref() {
            | Some(audience) => vld.set_audience(audience),
            | None => vld.set_issuer(&[&config.client.id]),
        }

        Ok(Self { kid, key, vld })
    }

    #[inline]
    fn decode(&self, token: &str) -> crate::Result<crate::TokenData> {
        jwt::decode(token, &self.key, &self.vld).map_err(From::from)
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
