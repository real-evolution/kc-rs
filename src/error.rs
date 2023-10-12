pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("url parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("uuid error: {0}")]
    Uuid(#[from] uuid::Error),
}
