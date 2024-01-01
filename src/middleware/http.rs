use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http::{header::AUTHORIZATION, Request};
use tower::{Layer, Service};

const BEARER_TOKEN_PREFIX: &'static str = "Bearer ";

pub type ServerAuthService<S> = AuthService<S, ServerMode>;
pub type ClientAuthService<S> = AuthService<S, ClientMode>;

pub type ServerAuthServiceLayer = AuthServiceLayer<ServerMode>;
pub type ClientAuthServiceLayer = AuthServiceLayer<ClientMode>;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct ServerMode;

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct ClientMode;

#[derive(Debug, Clone)]
pub struct AuthService<S, M> {
    kc: Arc<crate::ReCloak>,
    inner: S,
    _marker: PhantomData<M>,
}

#[derive(Debug, Clone)]
pub struct AuthServiceLayer<M = ()> {
    kc: Arc<crate::ReCloak>,
    _marker: PhantomData<M>,
}

#[derive(Debug, Clone, Copy)]
enum ServerAuthError {
    MissingHeader,
    InvalidHeader,
    InvalidToken,
}

impl ServerAuthServiceLayer {
    #[inline]
    pub const fn new(kc: Arc<crate::ReCloak>) -> Self {
        AuthServiceLayer {
            kc,
            _marker: PhantomData,
        }
    }
}

impl ClientAuthServiceLayer {
    #[inline]
    pub const fn new(kc: Arc<crate::ReCloak>) -> Self {
        AuthServiceLayer {
            kc,
            _marker: PhantomData,
        }
    }
}

impl<S, B> Service<Request<B>> for ServerAuthService<S>
where
    S: Service<Request<B>> + Clone + Send + 'static,
    S::Error: From<ServerAuthError>,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    type Response = S::Response;

    #[inline]
    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        if req.extensions().get::<crate::Token>().is_some() {
            return Box::pin(self.inner.call(req));
        }

        let Self { kc, inner, .. } = self.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        Box::pin(async move {
            let auth_header = req
                .headers()
                .get(AUTHORIZATION)
                .ok_or(ServerAuthError::MissingHeader)?;

            let header_str = auth_header
                .to_str()
                .map_err(|err| {
                    tracing::error!(error = %err, "failed to parse authorization header");

                    ServerAuthError::InvalidHeader
                })?;

            let bearer = header_str
                .strip_prefix(BEARER_TOKEN_PREFIX)
                .ok_or(ServerAuthError::InvalidToken)?;

            let token = kc
                .decode_token(bearer)
                .map_err(|err| {
                    tracing::error!(error = %err, "failed to parse authorization header");

                    ServerAuthError::InvalidToken
                })?;

            req.extensions_mut().insert(token.clone());

            inner.call(req).await
        })
    }
}

impl<S, B> Service<Request<B>> for ClientAuthService<S>
where
    S: Service<Request<B>> + Clone + Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    type Response = S::Response;

    #[inline]
    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(From::from)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        if req.headers().contains_key(AUTHORIZATION) {
            return Box::pin(self.inner.call(req));
        }

        let Self { kc, inner, .. } = self.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        Box::pin(async move {
            match kc.authenticate().await {
                | Ok(token) => {
                    let mut bearer = String::with_capacity(
                        BEARER_TOKEN_PREFIX.len() + token.len(),
                    );

                    bearer.push_str(BEARER_TOKEN_PREFIX);
                    bearer.push_str(&token);

                    match bearer.parse() {
                        | Ok(value) => {
                            req.headers_mut().insert(AUTHORIZATION, value);
                        }
                        | Err(err) => {
                            tracing::error!(error = %err, "failed to construct bearer token")
                        }
                    };
                }
                | Err(err) => {
                    tracing::error!(error = %err, "failed to authenticate, proceeding without token");

                    return inner.call(req).await;
                }
            };

            inner.call(req).await
        })
    }
}

impl<S, M> Layer<S> for AuthServiceLayer<M> {
    type Service = AuthService<S, M>;

    #[inline]
    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            kc: self.kc.clone(),
            inner,
            _marker: PhantomData,
        }
    }
}

impl std::fmt::Display for ServerAuthError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ServerAuthError::*;
        match self {
            | MissingHeader => write!(f, "missing authorization header"),
            | InvalidHeader => write!(f, "invalid authorization header"),
            | InvalidToken => write!(f, "invalid token"),
        }
    }
}

impl std::error::Error for ServerAuthError {}

impl From<ServerAuthError> for tonic::Status {
    #[inline]
    fn from(value: ServerAuthError) -> Self {
        tonic::Status::unauthenticated(value.to_string())
    }
}
