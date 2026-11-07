use redos_sentry::ast_analyzer::{analyze_regex, VulnerabilityClass};
use redos_sentry::fuzzer::{fuzz_and_benchmark, synthesize_attack_payload};
use redos_sentry::remediator::Remediator;
use redos_sentry::reporter::{PatternReport, Reporter, ScanReport};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

#[test]
fn test_detect_nested_quantifiers() {
    let finding1 = analyze_regex(r"(a+)+$").expect("Failed to parse");
    assert_eq!(
        finding1.class,
        VulnerabilityClass::ExponentialNestedQuantifier
    );
    assert_eq!(finding1.complexity_order, "O(2^n)");

    let finding2 = analyze_regex(r"([a-zA-Z]+)*").expect("Failed to parse");
    assert_eq!(
        finding2.class,
        VulnerabilityClass::ExponentialNestedQuantifier
    );
    assert_eq!(finding2.complexity_order, "O(2^n)");
}

#[test]
fn test_detect_overlapping_alternation() {
    let finding1 = analyze_regex(r"(a|ab)+$").expect("Failed to parse");
    assert_eq!(
        finding1.class,
        VulnerabilityClass::ExponentialOverlappingAlt
    );
    assert_eq!(finding1.complexity_order, "O(2^n)");

    let finding2 = analyze_regex(r"(x+|x+)+$").expect("Failed to parse");
    assert_eq!(
        finding2.class,
        VulnerabilityClass::ExponentialOverlappingAlt
    );
    assert_eq!(finding2.complexity_order, "O(2^n)");
}

#[test]
fn test_safe_regex_false_positive_guard() {
    let safe_patterns = [
        r"^[a-zA-Z0-9_-]{3,16}$",
        r"^[a-z]+@[a-z]+\.[a-z]+$",
        r"^\d{4}-\d{2}-\d{2}$",
        r"^[A-Z][a-z0-9]*$",
        r"^https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/.*)?$",
    ];

    for pattern in safe_patterns {
        let finding = analyze_regex(pattern).expect("Failed to parse safe pattern");
        assert_eq!(
            finding.class,
            VulnerabilityClass::Safe,
            "Expected safe for: {}",
            pattern
        );
        assert_eq!(finding.complexity_order, "O(n)");
    }
}

#[test]
fn test_attack_payload_synthesis() {
    let finding = analyze_regex(r"^prefix_(a+)+$").expect("Failed to parse");
    assert_eq!(
        finding.class,
        VulnerabilityClass::ExponentialNestedQuantifier
    );

    let payload = synthesize_attack_payload(&finding, 12);
    assert_eq!(payload, "prefix_aaaaaaaaaaaa!");
    assert!(payload.starts_with("prefix_"));
    assert!(payload.ends_with('!'));
}

#[test]
fn test_cli_table_and_json_output() {
    let finding_vuln = analyze_regex(r"(a+)+$").expect("Failed to parse");
    let finding_safe = analyze_regex(r"^[0-9]+$").expect("Failed to parse");

    assert!(finding_vuln.is_vulnerable());
    assert!(!finding_safe.is_vulnerable());

    let report_vuln = ScanReport {
        total_scanned: 1,
        vulnerable_count: 1,
        safe_count: 0,
        findings: vec![PatternReport {
            finding: finding_vuln,
            rewrite_suggestion: Some("a+".to_string()),
            explanation: Some("Exponential backtracking".to_string()),
            benchmark: None,
        }],
    };

    let json_output = Reporter::render_json(&report_vuln);
    assert!(json_output.contains("ExponentialNestedQuantifier"));
    assert!(json_output.contains("\"vulnerable_count\": 1"));

    let report_safe = ScanReport {
        total_scanned: 1,
        vulnerable_count: 0,
        safe_count: 1,
        findings: vec![PatternReport {
            finding: finding_safe,
            rewrite_suggestion: None,
            explanation: None,
            benchmark: None,
        }],
    };

    let safe_json = Reporter::render_json(&report_safe);
    assert!(safe_json.contains("\"safe_count\": 1"));
    assert!(safe_json.contains("\"vulnerable_count\": 0"));
}

#[test]
fn test_cve_fixtures_scanning() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("vulnerable_regexes.txt");

    let file = File::open(&fixture_path).expect("Could not open vulnerable_regexes.txt");
    let reader = BufReader::new(file);

    let mut scanned = 0;
    let mut vulnerable = 0;

    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let finding = analyze_regex(trimmed)
            .unwrap_or_else(|e| panic!("Failed to parse fixture '{}': {}", trimmed, e));

        scanned += 1;
        if finding.is_vulnerable() {
            vulnerable += 1;
        }
    }

    assert!(scanned > 0, "No fixture patterns were scanned");
    assert_eq!(
        scanned, vulnerable,
        "All fixture patterns must be recognized as vulnerable!"
    );
}

#[test]
fn test_fuzzer_growth_curve() {
    let finding = analyze_regex(r"(a+)+$").expect("Failed to parse");
    let benchmark = fuzz_and_benchmark(&finding, &[5, 10, 15], 100_000);

    assert_eq!(benchmark.steps.len(), 3);
    assert!(benchmark.confirmed_vulnerable);
    assert_eq!(benchmark.estimated_growth, "Exponential (O(2^n))");
}

#[test]
fn test_remediator_advice_generation() {
    let finding = analyze_regex(r"(a|ab)+$").expect("Failed to parse");
    let rewrite = Remediator::suggest_rewrite(&finding);
    assert!(!rewrite.is_empty());
    let explanation = Remediator::explain(&finding);
    assert!(explanation.contains("Pathology:"));
}
