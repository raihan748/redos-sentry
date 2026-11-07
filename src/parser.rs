//! Regex AST parsing module using pure-Rust `regex-syntax`.

use regex_syntax::hir::Hir;
use regex_syntax::ParserBuilder;
use std::fmt;

/// Error returned when regex syntax is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegexParseError {
    pub message: String,
    pub pattern: String,
}

impl fmt::Display for RegexParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Failed to parse regular expression '{}': {}",
            self.pattern, self.message
        )
    }
}

impl std::error::Error for RegexParseError {}

/// Parse a regular expression pattern string into a High-Level Intermediate Representation (`Hir`).
pub fn parse_regex(pattern: &str) -> Result<Hir, RegexParseError> {
    let mut builder = ParserBuilder::new();
    builder.unicode(true).utf8(true);
    let mut parser = builder.build();

    parser.parse(pattern).map_err(|e| RegexParseError {
        message: e.to_string(),
        pattern: pattern.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_regex() {
        let hir = parse_regex(r"^[a-zA-Z0-9]+$");
        assert!(hir.is_ok());
    }

    #[test]
    fn test_parse_invalid_regex() {
        let hir = parse_regex(r"(abc[");
        assert!(hir.is_err());
    }
}
