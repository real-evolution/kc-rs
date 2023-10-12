use std::collections::HashMap;

use serde_with::{DurationSeconds, TimestampSeconds};

pub type Token = jsonwebtoken::TokenData<Claims>;

#[serde_with::serde_as]
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Claims {
    #[serde(rename = "iss")]
    pub issuer: String,

    #[serde(rename = "sub")]
    pub subject: uuid::Uuid,

    #[serde(rename = "aud")]
    #[serde_as(as = "serde_with::OneOrMany<_>")]
    pub audience: Vec<String>,

    #[serde(rename = "exp")]
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub expires_at: chrono::DateTime<chrono::Utc>,

    #[serde(rename = "iat")]
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub issued_at: chrono::DateTime<chrono::Utc>,

    #[serde(rename = "jti")]
    pub id: uuid::Uuid,

    #[serde(rename = "preferred_username")]
    pub username: String,

    #[serde(rename = "realm_access")]
    pub realm: RolesClaim,

    #[serde(rename = "resource_access")]
    pub resource: HashMap<String, RolesClaim>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RolesClaim {
    #[serde(rename = "roles")]
    pub roles: Vec<String>,
}

#[serde_with::serde_as]
#[derive(Debug, serde::Deserialize)]
pub struct TokenContainer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    #[serde(rename = "access_token")]
    pub access_token: String,

    #[serde_as(as = "DurationSeconds<i64>")]
    pub expires_in: chrono::Duration,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub refresh_expires_in: Option<chrono::Duration>,
}

impl Claims {
    #[inline]
    pub fn is_subject(&self, rhs_id: impl TryInto<uuid::Uuid>) -> bool {
        rhs_id
            .try_into()
            .map(|id| self.subject == id)
            .unwrap_or(false)
    }

    #[inline]
    pub fn is_user(&self, username: &str) -> bool {
        self.username == username
    }

    #[inline]
    pub fn has_realm_role(&self, role: &str) -> bool {
        self.realm.roles.iter().any(|r| r == role)
    }

    #[inline]
    pub fn has_role(&self, client: &str, role: &str) -> bool {
        self.resource
            .get(client)
            .map(|r| r.roles.iter().any(|r| r == role))
            .unwrap_or(false)
    }
}
