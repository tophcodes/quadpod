//! Bytes for non-RDF resources, and the key that addresses them.
//!
//! The storage model of design spec §3.2. The key is the resource's own path,
//! so the backing store mirrors the URL tree and can be read with ordinary
//! tools; it is derived rather than recorded, which is what makes an
//! interrupted write or delete heal on the next write to the same URL instead
//! of leaking an object nobody can find.

use crate::space::ResourceUrl;
use bytes::Bytes;
use object_store::{path::Path, ObjectStore, ObjectStoreExt};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlobError {
    #[error("blob backend error: {0}")]
    Backend(String),
}

/// Longest path segment most filesystems accept, and longest whole path most
/// object stores accept — `object_store`'s own documented wording. Checked at
/// key construction so an over-long URL is refused with `414` before anything
/// is written, rather than failing inside a backend that phrases it
/// differently.
const MAX_SEGMENT_BYTES: usize = 255;
const MAX_PATH_BYTES: usize = 1024;

/// Where one resource's bytes live: its path with the leading `/` removed, so
/// `/photos/cat.png` is stored at `photos/cat.png`.
///
/// Constructible only through [`BlobKey::of`], which is what keeps the
/// derivation in one place — a second site building a key by hand is how two
/// resources come to share one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobKey(Path);

impl BlobKey {
    /// `None` when the mirrored key would exceed a segment or path length
    /// limit: a legal URL this pod cannot store (§3.2, §11).
    ///
    /// `Path::from` percent-encodes segments the backends treat as
    /// problematic, so a relative segment never reaches the backend as a
    /// directory ascent. That same encoding can expand a segment to up to
    /// three times its raw length, so the limits are measured on the
    /// encoded `Path`, not on the raw URL path.
    pub fn of(r: &ResourceUrl) -> Option<Self> {
        let rel = r.path().trim_start_matches('/');
        let path = Path::from(rel);
        if path.as_ref().len() > MAX_PATH_BYTES {
            return None;
        }
        if path.parts().any(|p| p.as_ref().len() > MAX_SEGMENT_BYTES) {
            return None;
        }
        Some(Self(path))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

/// Byte storage for non-RDF resources.
///
/// **Obligation on every implementor:** `put` writes the whole payload or
/// writes nothing; `delete` on an absent key succeeds; `get` distinguishes an
/// absent object from a backend it could not reach. The write order in design
/// spec §5.1 and the delete order in §7 rest on the first two, and neither can
/// check them.
///
/// Deliberately narrower than `object_store::ObjectStore`, whose multipart,
/// listing, copy and rename surface this pod does not use — and narrower on
/// purpose in the other direction too, since a remote Solid pod is a plausible
/// future implementor and is not an `ObjectStore`.
#[async_trait::async_trait]
pub trait BlobStore: Send + Sync {
    async fn put(&self, key: &BlobKey, bytes: Bytes) -> Result<(), BlobError>;
    async fn get(&self, key: &BlobKey) -> Result<Option<Bytes>, BlobError>;
    async fn delete(&self, key: &BlobKey) -> Result<(), BlobError>;
}

/// The `object_store`-backed implementation: in-process, local filesystem, or
/// anything else `object_store` reaches.
pub struct ObjectStoreBlobs(Arc<dyn ObjectStore>);

impl ObjectStoreBlobs {
    /// Bytes live for the process, matching `OxigraphStore::in_memory` — the
    /// pod stays uniformly ephemeral rather than making blobs outlive the
    /// triples that describe them.
    pub fn in_memory() -> Self {
        Self(Arc::new(object_store::memory::InMemory::new()))
    }

    /// A directory mirroring the URL tree (§3.2).
    pub fn local(root: &std::path::Path) -> Result<Self, BlobError> {
        object_store::local::LocalFileSystem::new_with_prefix(root)
            .map(|fs| Self(Arc::new(fs)))
            .map_err(|e| BlobError::Backend(e.to_string()))
    }
}

#[async_trait::async_trait]
impl BlobStore for ObjectStoreBlobs {
    async fn put(&self, key: &BlobKey, bytes: Bytes) -> Result<(), BlobError> {
        self.0
            .put(&key.0, bytes.into())
            .await
            .map(|_| ())
            .map_err(|e| BlobError::Backend(e.to_string()))
    }

    async fn get(&self, key: &BlobKey) -> Result<Option<Bytes>, BlobError> {
        match self.0.get(&key.0).await {
            Ok(r) => r
                .bytes()
                .await
                .map(Some)
                .map_err(|e| BlobError::Backend(e.to_string())),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(BlobError::Backend(e.to_string())),
        }
    }

    async fn delete(&self, key: &BlobKey) -> Result<(), BlobError> {
        match self.0.delete(&key.0).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(BlobError::Backend(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::{StorageSpace, Target};

    fn res(path: &str) -> crate::space::ResourceUrl {
        match StorageSpace::new("https://pod.toph.so/").unwrap().resolve(path).unwrap() {
            Target::Resource(r) => r,
            Target::Container(c) => c.as_resource().clone(),
            Target::Aux(_) => panic!("not a resource path"),
        }
    }

    // §3.2: the key mirrors the URL. Asserted on the key itself and not on a
    // round trip, because a round trip passes under ANY injective key
    // function — a hash included — and mirroring is the whole property.
    #[test]
    fn the_key_mirrors_the_resource_path() {
        assert_eq!(BlobKey::of(&res("/photos/cat.png")).unwrap().as_str(), "photos/cat.png");
        assert_eq!(BlobKey::of(&res("/notes")).unwrap().as_str(), "notes");
    }

    // Also asserted on the key: a `400` from somewhere upstream would make a
    // status-code assertion pass while proving nothing about BlobKey.
    #[test]
    fn a_relative_segment_never_reaches_the_backend_as_an_ascent() {
        // Whatever `resolve` admits, the key must not contain a `..` segment.
        for path in ["/a/b/c.txt", "/a/x.txt"] {
            let key = BlobKey::of(&res(path)).unwrap();
            assert!(
                !key.as_str().split('/').any(|s| s == ".." || s == "."),
                "{path} produced {}", key.as_str()
            );
            assert!(!key.as_str().starts_with('/'), "keys carry no leading slash");
        }
    }

    // §3.2: with a hash key every legal URL had a legal key. With a mirrored
    // one some do not, and the pod must say so rather than hand the backend a
    // name it will reject.
    #[test]
    fn an_over_long_segment_or_path_has_no_key() {
        let long_segment = "a".repeat(256);
        assert!(BlobKey::of(&res(&format!("/{long_segment}"))).is_none());

        let deep: String = std::iter::repeat_n("seg/", 300).collect();
        assert!(BlobKey::of(&res(&format!("/{deep}leaf"))).is_none());

        // The boundary itself is storable — an off-by-one here would refuse
        // legal URLs, which is the mirror-image bug.
        let at_limit = "a".repeat(255);
        assert!(BlobKey::of(&res(&format!("/{at_limit}"))).is_some());

        // `~` is legal and unescaped in a URL, but `object_store`'s
        // `PathPart` percent-encodes it anyway — one raw byte becomes three
        // stored bytes. The limits must bind on the stored length, not the
        // raw one: 255 raw `~` encode to 765 bytes and must have no key...
        let over_limit_encoded = "~".repeat(255);
        assert!(BlobKey::of(&res(&format!("/{over_limit_encoded}"))).is_none());

        // ...while 85 raw `~` encode to exactly 255 bytes and must still
        // have a key. Without this half, a fix that simply refuses anything
        // containing `~` would also pass.
        let at_limit_encoded = "~".repeat(85);
        assert!(BlobKey::of(&res(&format!("/{at_limit_encoded}"))).is_some());
    }

    #[tokio::test]
    async fn put_get_delete_round_trip() {
        let blobs = ObjectStoreBlobs::in_memory();
        let key = BlobKey::of(&res("/photos/cat.png")).unwrap();

        assert!(blobs.get(&key).await.unwrap().is_none(), "absent is None, not an error");

        // Bytes, not text: a NUL and invalid UTF-8 are what tell a byte path
        // apart from one that routes through String somewhere.
        let payload = bytes::Bytes::from_static(&[0x00, 0xff, 0xfe, b'\r', b'\n', 0x41]);
        blobs.put(&key, payload.clone()).await.unwrap();
        assert_eq!(blobs.get(&key).await.unwrap().unwrap(), payload);

        blobs.delete(&key).await.unwrap();
        assert!(blobs.get(&key).await.unwrap().is_none());

        // §4: deleting an absent object succeeds. The delete path in §7 has no
        // prior read, so this is load-bearing rather than tidy.
        blobs.delete(&key).await.unwrap();
    }

    #[tokio::test]
    async fn local_backend_writes_the_mirrored_tree_to_disk() {
        let dir = std::env::temp_dir().join(format!("sparql-pod-blob-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let blobs = ObjectStoreBlobs::local(&dir).unwrap();
        let key = BlobKey::of(&res("/photos/cat.png")).unwrap();

        blobs.put(&key, bytes::Bytes::from_static(b"png")).await.unwrap();

        // The point of mirroring: the file is where its URL says it is.
        assert_eq!(std::fs::read(dir.join("photos").join("cat.png")).unwrap(), b"png");
        std::fs::remove_dir_all(&dir).ok();
    }
}
