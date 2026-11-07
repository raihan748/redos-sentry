//! CLI entrypoint for `redos-sentry`.

use clap::Parser;
use redos_sentry::cli::Cli;
use redos_sentry::fuzzer::fuzz_and_benchmark;
use redos_sentry::remediator::Remediator;
use redos_sentry::reporter::{PatternReport, Reporter, ScanReport};
use redos_sentry::analyze_regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process;

fn main() {
    let cli = Cli::parse();

    let mut patterns = Vec::new();

    if let Some(ref p) = cli.pattern {
        patterns.push(p.clone());
    }

    if let Some(ref p) = cli.pattern_flag {
        patterns.push(p.clone());
    }

    if let Some(ref file_path) = cli.file {
        match File::open(file_path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        patterns.push(trimmed.to_string());
                    }
                }
            }
            Err(e) => {
                eprintln!("Error opening pattern file '{:?}': {}", file_path, e);
                process::exit(2);
            }
        }
    }

    if patterns.is_empty() {
        eprintln!("No regular expression patterns provided to analyze.");
        eprintln!("Usage: redos-sentry <PATTERN> or redos-sentry -f <FILE>");
        process::exit(0);
    }

    let step_sizes = cli.parse_step_sizes();
    let mut findings_reports = Vec::new();
    let mut vulnerable_count = 0;
    let mut safe_count = 0;

    for pat in &patterns {
        let finding = match analyze_regex(pat) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Warning: Failed to parse '{}': {}", pat, e);
                continue;
            }
        };

        if finding.is_vulnerable() {
            vulnerable_count += 1;
        } else {
            safe_count += 1;
        }

        let rewrite_suggestion = if cli.rewrite || !cli.json {
            Some(Remediator::suggest_rewrite(&finding))
        } else {
            None
        };

        let explanation = if cli.rewrite || !cli.json {
            Some(Remediator::explain(&finding))
        } else {
            None
        };

        let benchmark = if cli.fuzz && finding.is_vulnerable() {
            Some(fuzz_and_benchmark(&finding, &step_sizes, cli.max_steps))
        } else {
            None
        };

        findings_reports.push(PatternReport {
            finding,
            rewrite_suggestion,
            explanation,
            benchmark,
        });
    }

    let report = ScanReport {
        total_scanned: findings_reports.len(),
        vulnerable_count,
        safe_count,
        findings: findings_reports,
    };

    if cli.json {
        println!("{}", Reporter::render_json(&report));
    } else {
        Reporter::render_human(&report);
    }

    if report.vulnerable_count > 0 {
        process::exit(1);
    } else {
        process::exit(0);
    }
}
