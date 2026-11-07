//! Command line argument definitions for `redos-sentry`.

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "redos-sentry",
    author = "SMK Telkom Makassar Developer Team",
    version,
    about = "Static regex fuzzer and catastrophic backtracking (ReDoS) vulnerability analyzer",
    long_about = "A high-performance static analyzer and active fuzzer that detects ReDoS anti-patterns (nested quantifiers, overlapping alternations, pumpable prefixes), synthesizes attack vectors, and benchmarks execution complexity growth."
)]
pub struct Cli {
    /// Regular expression pattern to analyze
    #[arg(value_name = "PATTERN")]
    pub pattern: Option<String>,

    /// Specific pattern passed via option flag
    #[arg(short = 'p', long = "pattern", value_name = "REGEX")]
    pub pattern_flag: Option<String>,

    /// File containing regex patterns to scan (one per line)
    #[arg(short = 'f', long = "file", value_name = "PATH")]
    pub file: Option<PathBuf>,

    /// Run active backtracking fuzzer to benchmark execution growth curve
    #[arg(long = "fuzz")]
    pub fuzz: bool,

    /// Output report in structured JSON format for CI/CD integration
    #[arg(long = "json")]
    pub json: bool,

    /// Comma-separated list of repetition lengths for fuzzing (default: 5,10,15,20,25)
    #[arg(long = "steps", value_name = "SIZES", default_value = "5,10,15,20,25")]
    pub steps: String,

    /// Maximum backtracking steps per benchmark trial before timing out
    #[arg(long = "max-steps", value_name = "COUNT", default_value_t = 200_000)]
    pub max_steps: u64,

    /// Print safe rewrite recommendation and mathematical explanation
    #[arg(long = "rewrite")]
    pub rewrite: bool,
}

impl Cli {
    pub fn parse_step_sizes(&self) -> Vec<usize> {
        self.steps
            .split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .collect()
    }
}
