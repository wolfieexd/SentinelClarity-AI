pub const CORPUS_ROOT: &str = "contracts";

#[cfg(test)]
mod tests {
    #[test]
    fn corpus_crate_is_wired() {
        assert_eq!(super::CORPUS_ROOT, "contracts");
    }
}
