//! Terminal ANSI and JSON report formatting.

use crate::ast_analyzer::{VulnerabilityClass, VulnerabilityFinding};
use crate::fuzzer::FuzzBenchmarkResult;
use colored::Colorize;
use serde::Serialize;

/// Scan report aggregating one or more pattern analyses.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub total_scanned: usize,
    pub vulnerable_count: usize,
    pub safe_count: usize,
    pub findings: Vec<PatternReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PatternReport {
    pub finding: VulnerabilityFinding,
    pub rewrite_suggestion: Option<String>,
    pub explanation: Option<String>,
    pub benchmark: Option<FuzzBenchmarkResult>,
}

pub struct Reporter;

impl Reporter {
    /// Render report as formatted ANSI text to standard output.
    pub fn render_human(report: &ScanReport) {
        println!();
        println!(
            "{}",
            "=== redos-sentry Vulnerability Scan Report ==="
                .bold()
                .cyan()
        );
        println!(
            "Scanned: {} patterns | Vulnerable: {} | Safe: {}",
            report.total_scanned.to_string().bold(),
            report.vulnerable_count.to_string().red().bold(),
            report.safe_count.to_string().green().bold()
        );
        println!("{}", "--------------------------------------------------".dimmed());

        for (idx, item) in report.findings.iter().enumerate() {
            let f = &item.finding;
            println!(
                "\n{} Pattern #{}: {}",
                "[*]".cyan(),
                idx + 1,
                f.pattern.bold().yellow()
            );

            match f.class {
                VulnerabilityClass::ExponentialNestedQuantifier
                | VulnerabilityClass::ExponentialOverlappingAlt => {
                    println!(
                        "    Status     : {} ({})",
                        f.class.to_string().red().bold(),
                        f.complexity_order.red().bold()
                    );
                }
                VulnerabilityClass::PolynomialPumpablePrefix => {
                    println!(
                        "    Status     : {} ({})",
                        f.class.to_string().yellow().bold(),
                        f.complexity_order.yellow().bold()
                    );
                }
                VulnerabilityClass::Safe => {
                    println!(
                        "    Status     : {} ({})",
                        f.class.to_string().green().bold(),
                        f.complexity_order.green().bold()
                    );
                }
            }

            if f.is_vulnerable() {
                if !f.pump_char.is_empty() {
                    println!(
                        "    Synthesis  : prefix='{}', pump='{}', suffix='{}'",
                        f.pump_prefix, f.pump_char, f.non_match_suffix
                    );
                }
                if let Some(ref exp) = item.explanation {
                    println!("    Explanation: {}", exp.italic());
                }
                if let Some(ref rew) = item.rewrite_suggestion {
                    println!("    Advice     : {}", rew.green().bold());
                }

                if let Some(ref bm) = item.benchmark {
                    println!("    Growth Test: {}", bm.estimated_growth.bold());
                    for step in &bm.steps {
                        let status_str = if step.timed_out {
                            "TIMED OUT / LIMIT".red().bold()
                        } else {
                            format!("{} µs", step.duration_micros).normal()
                        };
                        println!(
                            "      len={:<3} -> {}",
                            step.input_length, status_str
                        );
                    }
                }
            }
        }

        println!();
        if report.vulnerable_count > 0 {
            println!(
                "{}",
                "FAILED: Catastrophic backtracking vulnerabilities detected!"
                    .red()
                    .bold()
            );
        } else {
            println!(
                "{}",
                "PASSED: All scanned regular expressions are linear and safe."
                    .green()
                    .bold()
            );
        }
    }

    /// Render report as structured JSON string.
    pub fn render_json(report: &ScanReport) -> String {
        serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
    }
}
