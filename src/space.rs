use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum SpaceError {
    #[error("base URI must be absolute (http:// or https://)")]
    NotAbsolute,
    #[error("base URI must end with a trailing slash")]
    NoTrailingSlash,
}

#[derive(Debug, Clone)]
pub struct StorageSpace {
    base: String,
}

impl StorageSpace {
    pub fn new(base: impl Into<String>) -> Result<Self, SpaceError> {
        let base = base.into();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            return Err(SpaceError::NotAbsolute);
        }
        if !base.ends_with('/') {
            return Err(SpaceError::NoTrailingSlash);
        }
        Ok(Self { base })
    }

    /// Map a request path to the absolute graph IRI, using the configured
    /// base only — the request host/scheme is deliberately ignored.
    pub fn graph_iri(&self, request_path: &str) -> String {
        let trimmed = request_path.strip_prefix('/').unwrap_or(request_path);
        format!("{}{}", self.base, trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_iri_uses_config_base_not_request_host() {
        let s = StorageSpace::new("https://pod.toph.so/").unwrap();
        assert_eq!(s.graph_iri("/foo"), "https://pod.toph.so/foo");
        assert_eq!(s.graph_iri("/a/b"), "https://pod.toph.so/a/b");
        assert_eq!(s.graph_iri("/"), "https://pod.toph.so/");
    }

    #[test]
    fn rejects_base_without_trailing_slash() {
        assert!(matches!(StorageSpace::new("https://pod.toph.so"),
            Err(SpaceError::NoTrailingSlash)));
    }

    #[test]
    fn rejects_non_absolute_base() {
        assert!(matches!(StorageSpace::new("pod.toph.so/"),
            Err(SpaceError::NotAbsolute)));
    }
}
