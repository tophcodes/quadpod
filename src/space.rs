use oxigraph::model::NamedNode;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum SpaceError {
    #[error("base URI must be absolute (http:// or https://)")]
    NotAbsolute,
    #[error("base URI must end with a trailing slash")]
    NoTrailingSlash,
    #[error("resource path does not form a valid IRI")]
    InvalidResourceIri,
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
    ///
    /// The result is validated as a well-formed absolute IRI before being
    /// returned, since it is later interpolated verbatim into SPARQL as
    /// `<{iri}>`: an unvalidated path (e.g. containing a decoded `>`, space,
    /// or `{`) could otherwise break out of the IRIREF and inject SPARQL.
    pub fn graph_iri(&self, request_path: &str) -> Result<String, SpaceError> {
        let trimmed = request_path.strip_prefix('/').unwrap_or(request_path);
        let iri = format!("{}{}", self.base, trimmed);
        NamedNode::new(&iri).map_err(|_| SpaceError::InvalidResourceIri)?;
        Ok(iri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_iri_uses_config_base_not_request_host() {
        let s = StorageSpace::new("https://pod.toph.so/").unwrap();
        assert_eq!(s.graph_iri("/foo").unwrap(), "https://pod.toph.so/foo");
        assert_eq!(s.graph_iri("/a/b").unwrap(), "https://pod.toph.so/a/b");
        assert_eq!(s.graph_iri("/").unwrap(), "https://pod.toph.so/");
    }

    #[test]
    fn graph_iri_rejects_iri_breaking_chars() {
        let s = StorageSpace::new("https://pod.toph.so/").unwrap();
        assert!(matches!(
            s.graph_iri("/foo> bar"),
            Err(SpaceError::InvalidResourceIri)
        ));
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
