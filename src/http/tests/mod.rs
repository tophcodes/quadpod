//! The HTTP layer's tests. They live in the crate because they reach private
//! items of `http` — `classify`, `accept_write`, `put_status`,
//! `allowed_methods`, `wac_allow_value` — which an integration binary under
//! `tests/` cannot see. Each file below is one subject; [`fixture`] holds the
//! `Fixture` and everything more than one of them needs.

mod fixture;

mod acl;
mod acl_links;
mod blobs;
mod conditionals;
mod containers;
mod cors_options;
mod datasets;
mod events;
mod formats;
mod paths;
mod patch;
mod rdf12;
mod shapes;
mod slash_pairs;
mod wac;
