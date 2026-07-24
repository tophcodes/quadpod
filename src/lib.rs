pub mod http;
pub mod resource;
pub mod space;
pub mod store;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        assert_eq!(2 + 2, 4);
    }
}
