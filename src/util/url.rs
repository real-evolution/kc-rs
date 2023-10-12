#[derive(Debug, Clone)]
pub struct UrlBuilder {
    buf: url::Url,
}

impl UrlBuilder {
    #[inline]
    pub fn new(url: impl AsRef<str>) -> crate::Result<Self> {
        let buf = url::Url::parse(url.as_ref())?;

        if buf.cannot_be_a_base() {
            return Err(crate::Error::from(url::ParseError::SetHostOnCannotBeABaseUrl))?;
        }

        Ok(Self { buf })
    }

    #[inline]
    pub fn push(mut self, path: impl AsRef<str>) -> Self {
        self.buf.path_segments_mut()
            .unwrap()
            .push(path.as_ref());
        self
    }

    pub fn take(self) -> url::Url {
        self.buf
    }
}
