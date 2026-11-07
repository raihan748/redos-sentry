//! redos-sentry
//! Static regex fuzzer and catastrophic backtracking (ReDoS) vulnerability analyzer.

pub mod ast_analyzer;
pub mod cli;
pub mod fuzzer;
pub mod parser;
pub mod remediator;
pub mod reporter;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use ast_analyzer::{analyze_hir, analyze_regex, VulnerabilityClass, VulnerabilityFinding};
pub use cli::Cli;
pub use fuzzer::{fuzz_and_benchmark, synthesize_attack_payload, FuzzBenchmarkResult, FuzzStep};
pub use parser::{parse_regex, RegexParseError};
pub use remediator::Remediator;
pub use reporter::{PatternReport, Reporter, ScanReport};
