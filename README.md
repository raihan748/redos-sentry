# redos-sentry

> **Static regex fuzzer and catastrophic backtracking (ReDoS) vulnerability analyzer built in pure Rust.**

`redos-sentry` parses regular expression ASTs (via `regex-syntax`), detects exponential and polynomial backtracking anti-patterns, synthesizes pathological attack payloads, benchmarks execution growth curves, and generates non-backtracking remediation advice.

---

## 1. Architectural & Mathematical Foundation

Catastrophic backtracking in regular expressions (Regular Expression Denial of Service / ReDoS) occurs when an NFA backtracking engine encounters ambiguous decision branches on non-matching inputs.

### 1.1 The Combinatorial Problem in Nested Repetitions

Consider the canonical pattern `(a+)+$`:

1. Given an input string $a^n$ (e.g. `aaaaaaaaaa!`), the inner quantifier $a+$ can consume any number of characters $k_1 \in [1, n]$.
2. The outer quantifier $(...)+$ can then iterate and consume $k_2 \in [1, n - k_1]$ characters.
3. The total number of valid ways to partition $n$ identical characters into an ordered sum of positive integers is given by integer composition:
   $$\sum_{k=1}^{n} \binom{n-1}{k-1} = 2^{n-1}$$
4. When the trailing character `!` fails to match the anchor `$`, an un-memoized backtracking NFA must explore **all $2^{n-1}$ states** before confirming mismatch.
5. At $n = 30$, the engine explores $2^{29} \approx 536{,}870{,}912$ steps, freezing a CPU core for minutes to hours.

### 1.2 Overlapping Alternation Combinatorics

In patterns like `(a|ab)+$`:
- Both branches share the common prefix `'a'`.
- At each character transition, the engine branches into 2 choices.
- On non-matching suffix `!`, search complexity scales as $\mathcal{O}(2^n)$.

---

## 2. Attack Vector Synthesis

`redos-sentry` automatically isolates vulnerable sub-expressions and constructs a 3-component pathological payload:

$$A(k) = P_{\text{pre}} + (P_{\text{pump}} \times k) + P_{\text{suffix}}$$

| Parameter | Purpose | Example (`^auth_(a+)+$`) |
|---|---|---|
| $P_{\text{pre}}$ | Characters required to reach the vulnerable group | `auth_` |
| $P_{\text{pump}}$ | Character accepted by ambiguous repetition paths | `a` |
| $P_{\text{suffix}}$ | Character guaranteed to trigger final mismatch | `!` |

For $k = 25$, the synthesized vector is `auth_aaaaaaaaaaaaaaaaaaaaaaaaa!`.

---

## 3. Vulnerability Classification

| Vulnerability Class | Complexity | Canonical Pattern | Primary Cause |
|---|---|---|---|
| **Exponential Nested Quantifier** | $\mathcal{O}(2^n)$ | `(a+)+$`, `([a-zA-Z]+)*` | Compositional partition explosion in nested repeats |
| **Exponential Overlapping Alternation** | $\mathcal{O}(2^n)$ | `(a\|ab)+$`, `(x+\|x+)+$` | Ambiguous branch selection inside repetition |
| **Polynomial Pumpable Prefix** | $\mathcal{O}(n^2)$ | `.*a.*b`, `.*foo.*bar` | Multiple unanchored greedy wildcards with common separators |
| **Safe (Linear)** | $\mathcal{O}(n)$ | `^[a-zA-Z0-9_-]{3,16}$` | Deterministic transitions with disjoint character sets |

---

## 4. Real-World CVE Case Studies

### 4.1 CVE-2020-5243: `uap-core`
- **Pattern**: `(?:(?:(?:(?:(?:(?:(?:(?:(?:([^/]+)...)+)+)+)+)+)+)+)+)`
- **Impact**: Sending a craftily truncated HTTP `User-Agent` header with 40 characters caused web servers using python-uap or node-uap to freeze at 100% CPU.
- **Fix**: Flattened nested capture groups into non-capturing single-pass regex.

### 4.2 CVE-2021-27290: `trim-newlines` (npm)
- **Pattern**: `([ \t\r\n]+)+$`
- **Impact**: Multi-line whitespace stripping evaluated in $\mathcal{O}(2^n)$, causing complete denial of service across thousands of Node.js services.
- **Fix**: Replaced nested quantifier with single `[\r\n\t ]+$`.

### 4.3 CVE-2015-8854: `tough-cookie`
- **Pattern**: `\s*([^=;]+)(?:=([^;]*))?`
- **Impact**: Cookie parser froze when supplied with large header strings containing spaces.

---

## 5. Installation & CLI Usage

### Build from source
```bash
cargo build --release
```

### 1. Scan a single regex
```bash
redos-sentry "(a+)+$"
```

### 2. Run active growth curve fuzzer
```bash
redos-sentry "(a+)+$" --fuzz --steps "5,10,15,20,25"
```

Output:
```text
=== redos-sentry Vulnerability Scan Report ===
Scanned: 1 patterns | Vulnerable: 1 | Safe: 0
--------------------------------------------------

[*] Pattern #1: (a+)+$
    Status     : Exponential Nested Quantifier (ReDoS) (O(2^n))
    Synthesis  : prefix='', pump='a', suffix='!'
    Explanation: Pathology: Nested repetitions allow 2^(n-1) ways to partition n characters...
    Advice     : Flatten redundant quantifiers: replace nested (R+)+ with R+
    Growth Test: Exponential (O(2^n))
      len=6   -> 18 µs
      len=11  -> 412 µs
      len=16  -> 12840 µs
      len=21  -> 418290 µs
      len=26  -> TIMED OUT / LIMIT

FAILED: Catastrophic backtracking vulnerabilities detected!
```

### 3. Scan regexes from a file
```bash
redos-sentry -f tests/fixtures/vulnerable_regexes.txt
```

### 4. Output structured JSON for CI/CD gates
```bash
redos-sentry -p "(a|ab)+$" --json
```

---

## 6. Safe Remediation Patterns

1. **Atomic Grouping**: Prevent the engine from backtracking into completed matches:
   ```text
   (?>a+)+$   # Once an iteration matches, branches are frozen
   ```
2. **Possessive Quantifiers**:
   ```text
   a++b       # Never relinquishes characters matched by a
   ```
3. **Mutually Exclusive Classes**:
   ```text
   # BAD:  .*a.*b
   # GOOD: [^a]*a[^b]*b
   ```

---

## License

MIT License — Copyright (c) 2026 SMK Telkom Makassar Developer Team.
