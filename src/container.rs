pub const LDP_CONTAINER: &str = "http://www.w3.org/ns/ldp#Container";
pub const LDP_BASIC_CONTAINER: &str = "http://www.w3.org/ns/ldp#BasicContainer";
pub const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";
pub const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

pub fn is_container_path(request_path: &str) -> bool {
    request_path.ends_with('/')
}

/// Parent container path (always trailing-slash), or None for the root "/".
pub fn parent_container(request_path: &str) -> Option<String> {
    if request_path == "/" {
        return None;
    }
    let trimmed = request_path.strip_suffix('/').unwrap_or(request_path);
    match trimmed.rfind('/') {
        Some(idx) => Some(trimmed[..=idx].to_string()),
        None => Some("/".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_paths_end_with_slash() {
        assert!(is_container_path("/foo/"));
        assert!(is_container_path("/"));
        assert!(!is_container_path("/foo"));
        assert!(!is_container_path("/a/b"));
    }

    #[test]
    fn parent_of_resource_and_container() {
        assert_eq!(parent_container("/a/b/c").as_deref(), Some("/a/b/"));
        assert_eq!(parent_container("/a/b/").as_deref(), Some("/a/"));
        assert_eq!(parent_container("/foo").as_deref(), Some("/"));
        assert_eq!(parent_container("/foo/").as_deref(), Some("/"));
        assert_eq!(parent_container("/"), None);
    }
}
