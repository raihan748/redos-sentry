//! Safe rewrite and remediation advisor for vulnerable regular expressions.

use crate::ast_analyzer::{VulnerabilityClass, VulnerabilityFinding};

/// Advisor that proposes safe, non-backtracking rewrites and explanations for vulnerable patterns.
pub struct Remediator;

impl Remediator {
    /// Generate an actionable, safe rewrite suggestion for a vulnerability finding.
    pub fn suggest_rewrite(finding: &VulnerabilityFinding) -> String {
        match finding.class {
            VulnerabilityClass::ExponentialNestedQuantifier => {
                Self::rewrite_nested_quantifier(&finding.pattern)
            }
            VulnerabilityClass::ExponentialOverlappingAlt => {
                Self::rewrite_overlapping_alternation(&finding.pattern)
            }
            VulnerabilityClass::PolynomialPumpablePrefix => {
                Self::rewrite_polynomial_prefix(&finding.pattern)
            }
            VulnerabilityClass::Safe => {
                "No rewrite needed; pattern executes in guaranteed linear time O(n).".to_string()
            }
        }
    }

    /// Generate an in-depth mathematical explanation of the ReDoS pathology.
    pub fn explain(finding: &VulnerabilityFinding) -> String {
        match finding.class {
            VulnerabilityClass::ExponentialNestedQuantifier => {
                format!(
                    "Pathology: Nested repetitions (e.g. (A+)+) allow 2^(n-1) ways to partition n matching characters across the inner and outer quantifiers. When followed by a non-matching character '{}', a backtracking NFA evaluates all 2^n paths, taking exponential time.",
                    finding.non_match_suffix
                )
            }
            VulnerabilityClass::ExponentialOverlappingAlt => {
                format!(
                    "Pathology: Multiple branches in the alternation accept the overlapping character '{}'. Within a repetition, each iteration branches into 2 choices. For an input of length n, the NFA explores 2^n decision branches before rejecting the input.",
                    finding.pump_char
                )
            }
            VulnerabilityClass::PolynomialPumpablePrefix => {
                "Pathology: Multiple unanchored greedy wildcards (e.g. .*a.*b) cause the first quantifier to consume the entire string, then backtrack character-by-character while the second quantifier attempts matching, generating O(n^2) or O(n^3) comparisons.".to_string()
            }
            VulnerabilityClass::Safe => {
                "Complexity: The regular expression AST contains deterministic, non-overlapping transitions that guarantee O(n) linear matching time regardless of input.".to_string()
            }
        }
    }

    fn rewrite_nested_quantifier(pattern: &str) -> String {
        // Flatten (a+)+ or ([a-z]+)+ to a+ or [a-z]+
        if let Some(inner) = pattern.strip_prefix('(').and_then(|s| s.strip_suffix(")+$").or_else(|| s.strip_suffix(")+"))) {
            if let Some(core) = inner.strip_suffix('+').or_else(|| inner.strip_suffix('*')) {
                return format!("{}+ (flattened single repetition) or (?>{})+ (atomic grouping)", core, inner);
            }
        }
        format!(
            "Flatten redundant quantifiers: replace nested (R+)+ with R+, or use atomic groups (?>...)+ or possessive quantifiers (R+)++"
        )
    }

    fn rewrite_overlapping_alternation(pattern: &str) -> String {
        // Example: (a|ab)+ -> (?:ab|a)+ or a+(?:b)*
        if pattern.contains("(a|ab)+") {
            return "Rewrite '(a|ab)+' as 'a+b*' or use atomic group '(?>a|ab)+' to prevent backtracking into 'a'".to_string();
        }
        "Factor out common prefixes: rewrite (A|AB) into A(B)? and make repetitions atomic (?>...)+".to_string()
    }

    fn rewrite_polynomial_prefix(pattern: &str) -> String {
        // Example: .*a.*b -> [^a]*a[^b]*b
        if pattern.contains(".*") {
            return pattern.replace(".*", "[^\\r\\n]*?") + " (or replace .* with negated character class [^delimiter]*)";
        }
        "Replace unanchored greedy .* with negated character classes [^delim]* or lazy quantifiers .*?".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explain_nested_quantifier() {
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
        let explanation = Remediator::explain(&finding);
        assert!(explanation.contains("Nested repetitions"));
        assert!(explanation.contains("2^n"));
    }

    #[test]
    fn test_suggest_rewrite() {
        let finding = VulnerabilityFinding {
            pattern: "(a|ab)+$".to_string(),
            class: VulnerabilityClass::ExponentialOverlappingAlt,
            complexity_order: "O(2^n)".to_string(),
            vulnerable_subpattern: "(a|ab)+".to_string(),
            pump_prefix: "".to_string(),
            pump_char: "a".to_string(),
            non_match_suffix: "!".to_string(),
            suggestion: "".to_string(),
        };
        let suggestion = Remediator::suggest_rewrite(&finding);
        assert!(suggestion.contains("atomic group") || suggestion.contains("Factor out"));
    }
}
