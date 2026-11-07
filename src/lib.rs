//! redos-sentry
//! Static regex fuzzer and catastrophic backtracking (ReDoS) vulnerability analyzer.

pub mod ast_analyzer;
pub mod parser;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use ast_analyzer::{analyze_regex, VulnerabilityClass, VulnerabilityFinding};
pub use parser::parse_regex;
