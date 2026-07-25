//! The authenticated caller of a request.

/// The identity attached to an incoming request after authentication.
///
/// `Public` means no credentials were presented (the request proceeds
/// unauthenticated); `WebId` carries the caller's verified WebID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Agent {
    Public,
    WebId(String),
}
