use std::sync::Arc;

use tonic::{
    metadata::MetadataValue,
    service::Interceptor,
    Extensions,
    Request,
    Status,
};

use crate::ReCloak;

#[derive(Debug, Clone)]
pub struct AuthInterceptor {
    kc: Arc<ReCloak>,
}

pub trait ExtensionMap {
    fn get_claims(&self) -> tonic::Result<Arc<crate::Claims>>;
}

impl AuthInterceptor {
    #[inline]
    pub const fn new(kc: Arc<ReCloak>) -> Self {
        Self { kc }
    }
}

impl Interceptor for AuthInterceptor {
    #[inline]
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> tonic::Result<tonic::Request<()>> {
        const AUTHORIZATION_KEY: &str = "authorization";
        const BEARER_TOKEN_PREFIX: &str = "Bearer ";

        let token = request
            .metadata()
            // get token metadata
            .get(AUTHORIZATION_KEY)
            .ok_or_else(|| Status::unauthenticated("missing auth header"))
            // convert to string
            .map(MetadataValue::to_str)?
            .map_err(|err| {
                tracing::warn!(?err, "invalid authorization header");
                Status::unauthenticated("invalid authorization header")
            })
            // strip bearer prefix
            .map(|h| h.trim_start_matches(BEARER_TOKEN_PREFIX))
            // decode token
            .map(|t| self.kc.decode_token(t))?
            .map_err(|err| {
                tracing::warn!(?err, "invalid token");
                Status::permission_denied("invalid token")
            })?;

        request.extensions_mut().insert(Arc::new(token.claims));

        Ok(request)
    }
}

impl ExtensionMap for Extensions {
    fn get_claims(&self) -> tonic::Result<Arc<crate::Claims>> {
        let Some(claims) = self.get::<Arc<crate::Claims>>() else {
            return Err(Status::unauthenticated(
                "missing authentication token",
            ));
        };

        Ok(claims.clone())
    }
}

impl<T> ExtensionMap for Request<T> {
    #[inline]
    fn get_claims(&self) -> tonic::Result<Arc<crate::Claims>> {
        self.extensions().get_claims()
    }
}
