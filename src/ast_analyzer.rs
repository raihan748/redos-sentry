//! Regex AST analyzer for ReDoS vulnerability detection.

use crate::parser::parse_regex;
use regex_syntax::hir::{Class, Hir, HirKind, Literal, Repetition};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Category of ReDoS vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnerabilityClass {
    /// Nested repetitions leading to exponential backtracking (e.g. `(a+)+`, `(a*)*`).
    ExponentialNestedQuantifier,
    /// Repetition over overlapping alternations (e.g. `(a|a)+`, `(a|ab)+`).
    ExponentialOverlappingAlt,
    /// Successive greedy wildcard repetitions leading to polynomial backtracking (e.g. `.*a.*b`).
    PolynomialPumpablePrefix,
    /// Linear time execution, safe from ReDoS.
    Safe,
}

impl std::fmt::Display for VulnerabilityClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExponentialNestedQuantifier => write!(f, "Exponential Nested Quantifier (ReDoS)"),
            Self::ExponentialOverlappingAlt => write!(f, "Exponential Overlapping Alternation (ReDoS)"),
            Self::PolynomialPumpablePrefix => write!(f, "Polynomial Pumpable Prefix (ReDoS)"),
            Self::Safe => write!(f, "Safe (Linear)"),
        }
    }
}

/// Vulnerability finding report containing diagnostic details and attack synthesis metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub pattern: String,
    pub class: VulnerabilityClass,
    pub complexity_order: String,
    pub vulnerable_subpattern: String,
    pub pump_prefix: String,
    pub pump_char: String,
    pub non_match_suffix: String,
    pub suggestion: String,
}

impl VulnerabilityFinding {
    pub fn is_vulnerable(&self) -> bool {
        self.class != VulnerabilityClass::Safe
    }
}

/// Analyze a regular expression pattern string for catastrophic backtracking vulnerabilities.
pub fn analyze_regex(pattern: &str) -> Result<VulnerabilityFinding, String> {
    let hir = parse_regex(pattern).map_err(|e| e.to_string())?;
    Ok(analyze_hir(pattern, &hir))
}

/// Analyze a parsed `Hir` AST for ReDoS patterns.
pub fn analyze_hir(pattern: &str, hir: &Hir) -> VulnerabilityFinding {
    // 1. Check for overlapping alternations inside repetitions (Exponential)
    if let Some((subpat, prefix, pump_char)) = find_overlapping_alternation_in_repetition(hir) {
        return VulnerabilityFinding {
            pattern: pattern.to_string(),
            class: VulnerabilityClass::ExponentialOverlappingAlt,
            complexity_order: "O(2^n)".to_string(),
            vulnerable_subpattern: subpat,
            pump_prefix: prefix,
            pump_char,
            non_match_suffix: "!".to_string(),
            suggestion: "Eliminate overlapping alternation branches, factor common prefixes, or use atomic groups."
                .to_string(),
        };
    }

    // 2. Check for nested quantifiers (Exponential)
    if let Some((subpat, prefix, pump_char)) = find_nested_quantifiers(hir) {
        return VulnerabilityFinding {
            pattern: pattern.to_string(),
            class: VulnerabilityClass::ExponentialNestedQuantifier,
            complexity_order: "O(2^n)".to_string(),
            vulnerable_subpattern: subpat,
            pump_prefix: prefix,
            pump_char,
            non_match_suffix: "!".to_string(),
            suggestion: "Flatten nested quantifiers or rewrite using mutually exclusive character classes."
                .to_string(),
        };
    }

    // 3. Check for polynomial pumpable prefixes (e.g. .*a.*b)
    if let Some((subpat, prefix, pump_char)) = find_polynomial_pumpable_prefix(hir) {
        return VulnerabilityFinding {
            pattern: pattern.to_string(),
            class: VulnerabilityClass::PolynomialPumpablePrefix,
            complexity_order: "O(n^2)".to_string(),
            vulnerable_subpattern: subpat,
            pump_prefix: prefix,
            pump_char,
            non_match_suffix: "!".to_string(),
            suggestion: "Avoid multiple unanchored greedy wildcards; replace with non-greedy or negated character classes."
                .to_string(),
        };
    }

    // Otherwise, safe linear regex
    VulnerabilityFinding {
        pattern: pattern.to_string(),
        class: VulnerabilityClass::Safe,
        complexity_order: "O(n)".to_string(),
        vulnerable_subpattern: String::new(),
        pump_prefix: String::new(),
        pump_char: String::new(),
        non_match_suffix: String::new(),
        suggestion: "Pattern exhibits linear time complexity and is safe from catastrophic backtracking."
            .to_string(),
    }
}

/// Check if a repetition is variable length / unbounded.
fn is_repeat_vulnerable(rep: &Repetition) -> bool {
    rep.max.is_none() || rep.max.unwrap() > 1
}

/// Recursively find overlapping alternations enclosed within an outer repetition.
fn find_overlapping_alternation_in_repetition(
    hir: &Hir,
) -> Option<(String, String, String)> {
    let mut prefix_acc = String::new();
    find_overlapping_alt_recursive(hir, &mut prefix_acc)
}

fn find_overlapping_alt_recursive(
    hir: &Hir,
    prefix_acc: &mut String,
) -> Option<(String, String, String)> {
    match hir.kind() {
        HirKind::Concat(list) => {
            for item in list {
                if let Some(res) = find_overlapping_alt_recursive(item, prefix_acc) {
                    return Some(res);
                }
                append_literal_prefix(item, prefix_acc);
            }
            None
        }
        HirKind::Capture(cap) => find_overlapping_alt_recursive(&cap.sub, prefix_acc),
        HirKind::Repetition(rep) if is_repeat_vulnerable(rep) => {
            if let Some((overlap_char, subpat)) = check_inner_alternation_overlap(&rep.sub) {
                return Some((subpat, prefix_acc.clone(), overlap_char.to_string()));
            }
            find_overlapping_alt_recursive(&rep.sub, prefix_acc)
        }
        _ => None,
    }
}

/// Check if an expression (or its immediate capture/concat wrapper) contains an alternation with overlapping branches.
fn check_inner_alternation_overlap(hir: &Hir) -> Option<(char, String)> {
    match hir.kind() {
        HirKind::Alternation(branches) => {
            if let Some(c) = find_overlap_in_branches(branches) {
                return Some((c, format_hir_subpattern(hir)));
            }
            None
        }
        HirKind::Capture(cap) => check_inner_alternation_overlap(&cap.sub),
        HirKind::Concat(list) if list.len() == 1 => check_inner_alternation_overlap(&list[0]),
        _ => None,
    }
}

/// Find a common character matched by at least two branches in an alternation.
fn find_overlap_in_branches(branches: &[Hir]) -> Option<char> {
    for i in 0..branches.len() {
        let chars_i = extract_sample_chars(&branches[i]);
        let set_i: HashSet<char> = chars_i.into_iter().collect();

        for j in (i + 1)..branches.len() {
            let chars_j = extract_sample_chars(&branches[j]);
            for c in chars_j {
                if set_i.contains(&c) {
                    return Some(c);
                }
            }
        }
    }
    None
}

/// Find nested quantifiers: an outer repetition containing another repetition in its subtree.
fn find_nested_quantifiers(hir: &Hir) -> Option<(String, String, String)> {
    let mut prefix_acc = String::new();
    find_nested_quantifiers_recursive(hir, &mut prefix_acc)
}

fn find_nested_quantifiers_recursive(
    hir: &Hir,
    prefix_acc: &mut String,
) -> Option<(String, String, String)> {
    match hir.kind() {
        HirKind::Concat(list) => {
            for item in list {
                if let Some(res) = find_nested_quantifiers_recursive(item, prefix_acc) {
                    return Some(res);
                }
                append_literal_prefix(item, prefix_acc);
            }
            None
        }
        HirKind::Capture(cap) => find_nested_quantifiers_recursive(&cap.sub, prefix_acc),
        HirKind::Repetition(rep) if is_repeat_vulnerable(rep) => {
            if let Some(inner_rep_hir) = find_inner_repetition(&rep.sub) {
                let pump_char = extract_first_char(inner_rep_hir).unwrap_or('a');
                let subpat = format_hir_subpattern(hir);
                return Some((subpat, prefix_acc.clone(), pump_char.to_string()));
            }
            find_nested_quantifiers_recursive(&rep.sub, prefix_acc)
        }
        _ => None,
    }
}

/// Check if a Hir sub-tree contains a repetition.
fn find_inner_repetition(hir: &Hir) -> Option<&Hir> {
    match hir.kind() {
        HirKind::Repetition(rep) => {
            if rep.max.is_none()
                || rep.max.unwrap() > 1
                || (rep.min == 0 && rep.max == Some(1))
            {
                Some(hir)
            } else {
                find_inner_repetition(&rep.sub)
            }
        }
        HirKind::Capture(cap) => find_inner_repetition(&cap.sub),
        HirKind::Concat(list) => {
            for item in list {
                if let Some(r) = find_inner_repetition(item) {
                    return Some(r);
                }
            }
            None
        }
        HirKind::Alternation(list) => {
            for item in list {
                if let Some(r) = find_inner_repetition(item) {
                    return Some(r);
                }
            }
            None
        }
        _ => None,
    }
}

/// Detect polynomial pumpable prefix, e.g. `.*a.*b`.
fn find_polynomial_pumpable_prefix(hir: &Hir) -> Option<(String, String, String)> {
    let mut prefix_acc = String::new();
    find_polynomial_prefix_recursive(hir, &mut prefix_acc)
}

fn find_polynomial_prefix_recursive(
    hir: &Hir,
    prefix_acc: &mut String,
) -> Option<(String, String, String)> {
    match hir.kind() {
        HirKind::Concat(list) => {
            // Find pairs of greedy repetitions in the concat list where the first repetition
            // can match the intervening token or the second repetition
            for i in 0..list.len() {
                if let HirKind::Repetition(rep1) = list[i].kind() {
                    if rep1.greedy && rep1.max.is_none() && is_wildcard_or_broad(&rep1.sub) {
                        for j in (i + 1)..list.len() {
                            if let HirKind::Repetition(rep2) = list[j].kind() {
                                if rep2.greedy && rep2.max.is_none() && is_wildcard_or_broad(&rep2.sub) {
                                    // Check if intermediate tokens can be swallowed by rep1
                                    let mut intermediate_swallowed = true;
                                    for k in (i + 1)..j {
                                        let sample = extract_first_char(&list[k]);
                                        if let Some(c) = sample {
                                            if !can_hir_match_char(&rep1.sub, c) {
                                                intermediate_swallowed = false;
                                                break;
                                            }
                                        }
                                    }
                                    if intermediate_swallowed {
                                        let pump_char = extract_first_char(&rep1.sub).unwrap_or('a');
                                        return Some((
                                            format_hir_subpattern(hir),
                                            prefix_acc.clone(),
                                            pump_char.to_string(),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                append_literal_prefix(&list[i], prefix_acc);
            }
            for item in list {
                if let Some(res) = find_polynomial_prefix_recursive(item, prefix_acc) {
                    return Some(res);
                }
            }
            None
        }
        HirKind::Capture(cap) => find_polynomial_prefix_recursive(&cap.sub, prefix_acc),
        _ => None,
    }
}

/// Check if a Hir is a wildcard (e.g. `.` which matches almost all unicode chars).
fn is_wildcard_or_broad(hir: &Hir) -> bool {
    match hir.kind() {
        HirKind::Class(Class::Unicode(u)) => {
            let total: usize = u.iter().map(|r| (r.end() as u32 - r.start() as u32 + 1) as usize).sum();
            total >= 1000 // Wildcard `.` matches >= 1,000,000 characters
        }
        HirKind::Class(Class::Bytes(b)) => {
            let total: usize = b.iter().map(|r| (r.end() as u32 - r.start() as u32 + 1) as usize).sum();
            total >= 200
        }
        _ => false,
    }
}

/// Check if a Hir can match a specific char.
fn can_hir_match_char(hir: &Hir, c: char) -> bool {
    match hir.kind() {
        HirKind::Literal(Literal(bytes)) => {
            if let Ok(s) = std::str::from_utf8(bytes) {
                s.contains(c)
            } else {
                false
            }
        }
        HirKind::Class(Class::Unicode(u)) => u.iter().any(|r| r.start() <= c && c <= r.end()),
        HirKind::Class(Class::Bytes(b)) => {
            let b_val = c as u32;
            if b_val <= 255 {
                b.iter().any(|r| r.start() <= (b_val as u8) && (b_val as u8) <= r.end())
            } else {
                false
            }
        }
        HirKind::Repetition(rep) => can_hir_match_char(&rep.sub, c),
        HirKind::Capture(cap) => can_hir_match_char(&cap.sub, c),
        HirKind::Alternation(list) => list.iter().any(|a| can_hir_match_char(a, c)),
        HirKind::Concat(list) => list.iter().any(|item| can_hir_match_char(item, c)),
        _ => false,
    }
}

/// Extract sample characters accepted by this Hir.
fn extract_sample_chars(hir: &Hir) -> Vec<char> {
    let mut result = Vec::new();
    match hir.kind() {
        HirKind::Literal(Literal(bytes)) => {
            if let Ok(s) = std::str::from_utf8(bytes) {
                if let Some(first) = s.chars().next() {
                    result.push(first);
                }
            }
        }
        HirKind::Class(Class::Unicode(u)) => {
            for range in u.iter() {
                let start = range.start();
                let end = range.end();
                result.push(start);
                if (start as u32) < (end as u32) {
                    if let Some(next_c) = char::from_u32(start as u32 + 1) {
                        result.push(next_c);
                    }
                }
                if result.len() >= 30 {
                    break;
                }
            }
        }
        HirKind::Class(Class::Bytes(b)) => {
            for range in b.iter() {
                result.push(range.start() as char);
                if result.len() >= 30 {
                    break;
                }
            }
        }
        HirKind::Repetition(rep) => {
            result.extend(extract_sample_chars(&rep.sub));
        }
        HirKind::Capture(cap) => {
            result.extend(extract_sample_chars(&cap.sub));
        }
        HirKind::Concat(list) => {
            for item in list {
                let sub_chars = extract_sample_chars(item);
                if !sub_chars.is_empty() {
                    result.extend(sub_chars);
                    break;
                }
            }
        }
        HirKind::Alternation(list) => {
            for item in list {
                result.extend(extract_sample_chars(item));
            }
        }
        _ => {}
    }
    result
}

/// Extract the first representative character.
fn extract_first_char(hir: &Hir) -> Option<char> {
    extract_sample_chars(hir).into_iter().next()
}

/// Append literal prefix if item is a literal.
fn append_literal_prefix(item: &Hir, prefix_acc: &mut String) {
    if let HirKind::Literal(Literal(bytes)) = item.kind() {
        if let Ok(s) = std::str::from_utf8(bytes) {
            prefix_acc.push_str(s);
        }
    }
}

/// Format a Hir subpattern description.
fn format_hir_subpattern(hir: &Hir) -> String {
    format!("{:?}", hir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_nested_quantifiers() {
        let finding1 = analyze_regex(r"(a+)+$").expect("Failed to analyze");
        assert_eq!(finding1.class, VulnerabilityClass::ExponentialNestedQuantifier);
        assert_eq!(finding1.complexity_order, "O(2^n)");

        let finding2 = analyze_regex(r"([a-zA-Z]+)*").expect("Failed to analyze");
        assert_eq!(finding2.class, VulnerabilityClass::ExponentialNestedQuantifier);
        assert_eq!(finding2.complexity_order, "O(2^n)");
    }

    #[test]
    fn test_detect_overlapping_alternation() {
        let finding1 = analyze_regex(r"(a|ab)+$").expect("Failed to analyze");
        assert_eq!(finding1.class, VulnerabilityClass::ExponentialOverlappingAlt);
        assert_eq!(finding1.complexity_order, "O(2^n)");

        let finding2 = analyze_regex(r"(x+|x+)+$").expect("Failed to analyze");
        assert_eq!(finding2.class, VulnerabilityClass::ExponentialOverlappingAlt);
        assert_eq!(finding2.complexity_order, "O(2^n)");
    }

    #[test]
    fn test_safe_regex_false_positive_guard() {
        let finding1 = analyze_regex(r"^[a-zA-Z0-9_-]{3,16}$").expect("Failed to analyze");
        assert_eq!(finding1.class, VulnerabilityClass::Safe);
        assert_eq!(finding1.complexity_order, "O(n)");

        let finding2 = analyze_regex(r"^[a-z]+@[a-z]+\.[a-z]+$").expect("Failed to analyze");
        assert_eq!(finding2.class, VulnerabilityClass::Safe);
        assert_eq!(finding2.complexity_order, "O(n)");
    }

    #[test]
    fn test_polynomial_pumpable_prefix() {
        let finding = analyze_regex(r".*a.*b").expect("Failed to analyze");
        assert_eq!(finding.class, VulnerabilityClass::PolynomialPumpablePrefix);
        assert_eq!(finding.complexity_order, "O(n^2)");
    }
}
