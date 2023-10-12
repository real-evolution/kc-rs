use std::sync::Arc;

use crate::{Claims, ReCloak};

const AUTHORIZATION_KEY: &str = "authorization";
const BEARER_TOKEN_PREFIX: &str = "Bearer ";

pub trait RequestExt {
    fn authenticate(&self) -> Result<&crate::Claims, tonic::Status>;

    fn authorize(
        &self,
        pred: impl FnOnce(&Claims) -> bool,
    ) -> Result<&crate::Claims, tonic::Status>;
}

#[derive(Debug, Clone)]
pub struct AuthInterceptor {
    kc: Arc<ReCloak>,
}

impl AuthInterceptor {
    #[inline]
    pub const fn new(kc: Arc<ReCloak>) -> Self {
        Self { kc }
    }

    pub fn intercept(
        &mut self,
        mut req: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        let token = req
            .metadata_mut()
            .get(AUTHORIZATION_KEY)
            .ok_or_else(|| {
                tonic::Status::unauthenticated("missing authorization header")
            })?
            .to_str()
            .map(|hdr| hdr.trim_start_matches(BEARER_TOKEN_PREFIX))
            .map_err(|err| {
                tracing::warn!(err = %err, "could not parse authorization header");

                tonic::Status::unauthenticated("invalid authorization header")
            })?;

        let claims = self
            .kc
            .decode_token(token)
            .map_err(|err| {
                tracing::warn!(err = %err, "could not decode token");

                tonic::Status::unauthenticated("invalid token")
            })?
            .claims;

        req.extensions_mut().insert(claims);

        Ok(req)
    }
}

impl tonic::service::Interceptor for AuthInterceptor {
    #[inline]
    fn call(
        &mut self,
        request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        self.intercept(request)
    }
}

impl<T> RequestExt for tonic::Request<T> {
    fn authenticate(&self) -> Result<&crate::Claims, tonic::Status> {
        self.extensions().get::<crate::Claims>().ok_or_else(|| {
            tonic::Status::unauthenticated("missing authentication token")
        })
    }

    fn authorize(
        &self,
        pred: impl FnOnce(&Claims) -> bool,
    ) -> Result<&crate::Claims, tonic::Status> {
        let claims = self.authenticate()?;

        if !pred(claims) {
            return Err(tonic::Status::permission_denied(
                "insufficient permissions",
            ));
        }

        Ok(claims)
    }
}
