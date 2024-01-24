use std::collections::HashMap;

use serde_with::TimestampSeconds;

pub type TokenData = jsonwebtoken::TokenData<Claims>;

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

impl Claims {
    #[inline]
    pub fn is_subject(&self, rhs_id: impl TryInto<uuid::Uuid>) -> bool {
        rhs_id
            .try_into()
            .map(|id| self.subject == id)
            .unwrap_or(false)
    }

    #[inline]
    pub fn is_user(&self, username: impl AsRef<str>) -> bool {
        self.username == username.as_ref()
    }

    #[inline]
    pub fn has_realm_role(&self, role: impl AsRef<str>) -> bool {
        self.realm.roles.iter().any(|r| r == role.as_ref())
    }

    #[inline]
    pub fn has_role(
        &self,
        client_id: impl AsRef<str>,
        role: impl AsRef<str>,
    ) -> bool {
        self.resource
            .get(client_id.as_ref())
            .map(|r| r.roles.iter().any(|r| r == role.as_ref()))
            .unwrap_or(false)
    }
}
