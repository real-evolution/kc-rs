use std::{
    future::Future,
    marker::PhantomData,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{BufMut, BytesMut};
use http::{header::AUTHORIZATION, HeaderValue, Request};
use tower::{Layer, Service};

const BEARER_TOKEN_PREFIX: &str = "Bearer ";

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub type ServerAuthService<S, E = BoxError> = AuthService<S, ServerMode, E>;
pub type ClientAuthService<S, E = BoxError> = AuthService<S, ClientMode, E>;

pub type ServerAuthServiceLayer<E = BoxError> = AuthServiceLayer<ServerMode, E>;
pub type ClientAuthServiceLayer<E = BoxError> = AuthServiceLayer<ClientMode, E>;

#[derive(Debug, Clone)]
pub struct RequestAuthorization {
    claims: crate::Claims,
    auth_header: HeaderValue,
}

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct ServerMode;

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct ClientMode;

#[derive(Debug)]
pub struct AuthService<S, M, E> {
    kc: Arc<crate::ReCloak>,
    inner: S,
    _marker: PhantomData<(M, E)>,
}

#[derive(Debug, Clone)]
pub struct AuthServiceLayer<M, E> {
    kc: Arc<crate::ReCloak>,
    _marker: PhantomData<(M, E)>,
}

#[derive(Debug, Clone, Copy)]
enum ServerAuthError {
    MissingHeader,
    InvalidHeader,
    InvalidToken,
}

impl ServerAuthServiceLayer {
    #[inline]
    pub const fn new<E>(kc: Arc<crate::ReCloak>) -> ServerAuthServiceLayer<E> {
        AuthServiceLayer {
            kc,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub const fn for_grpc(
        kc: Arc<crate::ReCloak>,
    ) -> ServerAuthServiceLayer<tonic::Status> {
        ServerAuthServiceLayer::new(kc)
    }
}

impl<E> ClientAuthServiceLayer<E> {
    #[inline]
    pub const fn new(kc: Arc<crate::ReCloak>) -> Self {
        AuthServiceLayer {
            kc,
            _marker: PhantomData,
        }
    }
}

impl<S, E, B> Service<Request<B>> for ServerAuthService<S, E>
where
    S: Service<Request<B>> + Clone + Send + 'static,
    S::Error: From<E>,
    S::Future: Send + 'static,
    B: Send + 'static,
    E: From<ServerAuthError>,
{
    type Error = S::Error;
    type Response = S::Response;

    type Future = impl Future<Output = Result<Self::Response, Self::Error>>;

    #[inline]
    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let Self { kc, inner, .. } = self.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        async move {
            if req.extensions().get::<crate::Claims>().is_some() {
                return inner.call(req).await;
            }

            let auth_header = req
                .headers()
                .get(AUTHORIZATION)
                .ok_or(ServerAuthError::MissingHeader.into())?
                .clone();

            let header_str = auth_header
                .to_str()
                .map_err(|err| {
                    tracing::error!(error = %err, "failed to parse authorization header");

                    ServerAuthError::InvalidHeader.into()
                })?;

            let bearer = header_str
                .strip_prefix(BEARER_TOKEN_PREFIX)
                .ok_or(ServerAuthError::InvalidToken.into())?;

            let token = kc
                .decode_token(bearer)
                .map_err(|err| {
                    tracing::error!(error = %err, "failed to parse authorization header");

                    ServerAuthError::InvalidToken.into()
                })?;

            req.extensions_mut().insert(RequestAuthorization {
                claims: token.claims,
                auth_header,
            });

            inner.call(req).await
        }
    }
}

impl<S, E, B> Service<Request<B>> for ClientAuthService<S, E>
where
    S: Service<Request<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    E: From<S::Error>,
    B: Send + 'static,
{
    type Error = S::Error;
    type Response = S::Response;

    type Future = impl Future<Output = Result<Self::Response, Self::Error>>;

    #[inline]
    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(From::from)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let Self { kc, inner, .. } = self.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        async move {
            if req.extensions().get::<crate::Claims>().is_some() {
                return inner.call(req).await;
            }

            match kc.authenticate().await {
                | Ok(token) => {
                    let mut buf = BytesMut::with_capacity(
                        BEARER_TOKEN_PREFIX.len() + token.as_bytes().len(),
                    );

                    buf.put(BEARER_TOKEN_PREFIX.as_bytes());
                    buf.put_slice(token.as_bytes());

                    // Safety: we know the buffer is valid utf-8, since we
                    // the token always comes from a valid source.
                    let value = unsafe {
                        HeaderValue::from_maybe_shared_unchecked(buf.freeze())
                    };

                    req.headers_mut().insert(AUTHORIZATION, value);
                }
                | Err(err) => {
                    tracing::error!(error = %err, "failed to authenticate, proceeding without token");

                    return inner.call(req).await;
                }
            };

            inner.call(req).await
        }
    }
}

impl<S, M, E> Layer<S> for AuthServiceLayer<M, E> {
    type Service = AuthService<S, M, E>;

    #[inline]
    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            kc: self.kc.clone(),
            inner,
            _marker: PhantomData,
        }
    }
}

impl<S, M, E> Clone for AuthService<S, M, E>
where
    S: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            kc: self.kc.clone(),
            inner: self.inner.clone(),
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

impl RequestAuthorization {
    #[inline]
    pub const fn claims(&self) -> &crate::Claims {
        &self.claims
    }

    #[inline]
    pub fn authorization_header(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(self.auth_header.as_bytes()) }
    }
}
