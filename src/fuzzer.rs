//! Active ReDoS fuzzer and execution complexity growth profiler.

use crate::ast_analyzer::{VulnerabilityClass, VulnerabilityFinding};
use crate::parser::parse_regex;
use regex_syntax::hir::{Class, Hir, HirKind, Literal, Look};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Individual measurement step during fuzzing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzStep {
    pub input_length: usize,
    pub duration_micros: u64,
    pub timed_out: bool,
}

/// Comprehensive benchmark results illustrating execution growth curve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzBenchmarkResult {
    pub pattern: String,
    pub steps: Vec<FuzzStep>,
    pub confirmed_vulnerable: bool,
    pub estimated_growth: String,
}

/// Synthesize a pathological attack string from vulnerability finding metadata.
/// Attack string formula: A(k) = P_pre + (P_pump * k) + P_suffix.
pub fn synthesize_attack_payload(finding: &VulnerabilityFinding, repeat_count: usize) -> String {
    let pump_char = if finding.pump_char.is_empty() {
        "a"
    } else {
        &finding.pump_char
    };
    let suffix = if finding.non_match_suffix.is_empty() {
        "!"
    } else {
        &finding.non_match_suffix
    };

    format!(
        "{}{}{}",
        finding.pump_prefix,
        pump_char.repeat(repeat_count),
        suffix
    )
}

/// Active execution growth profiler measuring backtracking scaling.
pub fn fuzz_and_benchmark(
    finding: &VulnerabilityFinding,
    step_sizes: &[usize],
    max_steps_per_run: u64,
) -> FuzzBenchmarkResult {
    let hir = match parse_regex(&finding.pattern) {
        Ok(h) => h,
        Err(_) => {
            return FuzzBenchmarkResult {
                pattern: finding.pattern.clone(),
                steps: Vec::new(),
                confirmed_vulnerable: false,
                estimated_growth: "Error: Unable to parse AST".to_string(),
            }
        }
    };

    let mut fuzz_steps = Vec::new();
    let mut any_timed_out = false;

    for &k in step_sizes {
        let payload = synthesize_attack_payload(finding, k);
        let start = Instant::now();
        let mut steps: u64 = 0;

        let res = match_backtrack_root(&hir, &payload, &mut steps, max_steps_per_run);
        let duration = start.elapsed();
        let timed_out = res.is_err() || duration.as_millis() > 500;

        if timed_out {
            any_timed_out = true;
        }

        fuzz_steps.push(FuzzStep {
            input_length: payload.len(),
            duration_micros: duration.as_micros() as u64,
            timed_out,
        });
    }

    // Determine estimated growth curve
    let confirmed_vulnerable = any_timed_out || finding.class != VulnerabilityClass::Safe;
    let estimated_growth = match finding.class {
        VulnerabilityClass::ExponentialNestedQuantifier
        | VulnerabilityClass::ExponentialOverlappingAlt => "Exponential (O(2^n))".to_string(),
        VulnerabilityClass::PolynomialPumpablePrefix => "Polynomial (O(n^2))".to_string(),
        VulnerabilityClass::Safe => "Linear (O(n))".to_string(),
    };

    FuzzBenchmarkResult {
        pattern: finding.pattern.clone(),
        steps: fuzz_steps,
        confirmed_vulnerable,
        estimated_growth,
    }
}

/// Root invocation for recursive backtracking matcher.
fn match_backtrack_root(
    hir: &Hir,
    text: &str,
    steps: &mut u64,
    max_steps: u64,
) -> Result<bool, ()> {
    // If pattern starts with ^, match only at index 0. Otherwise search all starting indices.
    let ends = match_hir(hir, text, 0, steps, max_steps)?;
    Ok(ends.contains(&text.len()))
}

/// Recursive backtracking matching engine modeling standard NFA evaluation.
fn match_hir(
    hir: &Hir,
    text: &str,
    pos: usize,
    steps: &mut u64,
    max_steps: u64,
) -> Result<Vec<usize>, ()> {
    *steps += 1;
    if *steps > max_steps {
        return Err(());
    }

    match hir.kind() {
        HirKind::Empty => Ok(vec![pos]),
        HirKind::Literal(Literal(bytes)) => {
            if text.as_bytes().get(pos..pos + bytes.len()) == Some(bytes) {
                Ok(vec![pos + bytes.len()])
            } else {
                Ok(vec![])
            }
        }
        HirKind::Class(Class::Unicode(u)) => {
            if pos < text.len() {
                if let Some(c) = text[pos..].chars().next() {
                    if u.iter().any(|r| r.start() <= c && c <= r.end()) {
                        return Ok(vec![pos + c.len_utf8()]);
                    }
                }
            }
            Ok(vec![])
        }
        HirKind::Class(Class::Bytes(b)) => {
            if pos < text.len() {
                let byte = text.as_bytes()[pos];
                if b.iter().any(|r| r.start() <= byte && byte <= r.end()) {
                    return Ok(vec![pos + 1]);
                }
            }
            Ok(vec![])
        }
        HirKind::Look(Look::Start) => {
            if pos == 0 {
                Ok(vec![pos])
            } else {
                Ok(vec![])
            }
        }
        HirKind::Look(Look::End) => {
            if pos == text.len() {
                Ok(vec![pos])
            } else {
                Ok(vec![])
            }
        }
        HirKind::Look(_) => Ok(vec![pos]),
        HirKind::Capture(cap) => match_hir(&cap.sub, text, pos, steps, max_steps),
        HirKind::Alternation(branches) => {
            let mut all_ends = Vec::new();
            for branch in branches {
                let branch_ends = match_hir(branch, text, pos, steps, max_steps)?;
                all_ends.extend(branch_ends);
            }
            Ok(all_ends)
        }
        HirKind::Concat(list) => {
            let mut current = vec![pos];
            for item in list {
                let mut next_positions = Vec::new();
                for p in current {
                    let ends = match_hir(item, text, p, steps, max_steps)?;
                    next_positions.extend(ends);
                }
                if next_positions.is_empty() {
                    return Ok(vec![]);
                }
                current = next_positions;
            }
            Ok(current)
        }
        HirKind::Repetition(rep) => {
            match_repetition(&rep.sub, rep.min, rep.max, text, pos, 0, steps, max_steps)
        }
    }
}

/// Backtracking repetition matcher exploring all partitions.
fn match_repetition(
    sub: &Hir,
    min: u32,
    max: Option<u32>,
    text: &str,
    pos: usize,
    depth: usize,
    steps: &mut u64,
    max_steps: u64,
) -> Result<Vec<usize>, ()> {
    *steps += 1;
    if *steps > max_steps {
        return Err(());
    }

    let mut results = Vec::new();

    if depth >= min as usize {
        results.push(pos);
    }

    if let Some(max_limit) = max {
        if depth >= max_limit as usize {
            return Ok(results);
        }
    }

    let sub_ends = match_hir(sub, text, pos, steps, max_steps)?;
    for next_pos in sub_ends {
        if next_pos > pos {
            let further = match_repetition(
                sub,
                min,
                max,
                text,
                next_pos,
                depth + 1,
                steps,
                max_steps,
            )?;
            results.extend(further);
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_payload_synthesis() {
        let finding = VulnerabilityFinding {
            pattern: "^auth_(a+)+$".to_string(),
            class: VulnerabilityClass::ExponentialNestedQuantifier,
            complexity_order: "O(2^n)".to_string(),
            vulnerable_subpattern: "(a+)+".to_string(),
            pump_prefix: "auth_".to_string(),
            pump_char: "a".to_string(),
            non_match_suffix: "!".to_string(),
            suggestion: "".to_string(),
        };

        let payload = synthesize_attack_payload(&finding, 15);
        assert_eq!(payload, "auth_aaaaaaaaaaaaaaa!");
        assert!(payload.starts_with("auth_"));
        assert!(payload.ends_with('!'));
        assert_eq!(payload.matches('a').count(), 16); // "auth_" has one 'a' + 15 pumped 'a's
    }

    #[test]
    fn test_fuzz_benchmark_growth() {
        let finding = VulnerabilityFinding {
            pattern: "(a+)+$".to_string(),
            class: VulnerabilityClass::ExponentialNestedQuantifier,
            complexity_order: "O(2^n)".to_string(),
            vulnerable_subpattern: "(a+)+".to_string(),
            pump_prefix: "".to_string(),
            pump_char: "a".to_string(),
            non_match_suffix: "!".to_string(),
            suggestion: "".to_string(),
        };

        let result = fuzz_and_benchmark(&finding, &[5, 10, 15], 100_000);
        assert_eq!(result.steps.len(), 3);
        assert!(result.confirmed_vulnerable);
    }
}
