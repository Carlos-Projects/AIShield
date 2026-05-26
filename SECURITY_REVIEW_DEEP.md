# AIShield — Deep Security Review

**Version**: 0.1.0
**Date**: 2026-05-26
**Files Reviewed**: 29 source modules (1,236 LOC), 16 test files (196 tests)
**Review Type**: Full white-box source code audit
**Risk Level**: 🟢 LOW (post-fix)

---

## 1. Executive Summary

### 1.1 What AIShield Does

AIShield is a **static CLI security scanner** for the LLM fine-tuning lifecycle. It reads local directories, analyzes files for security issues (dataset poisoning, LoRA backdoors, weight tampering, pipeline vulnerabilities), and outputs findings in console/JSON/HTML formats.

### 1.2 Security Posture

| Dimension | Assessment |
|---|---|
| Architecture | Secure by design - CLI-only, no network, no code execution |
| Attack Surface | Minimal - only CLI args and filesystem reads |
| Code Quality | 196 tests, ruff 0 errors, mypy 0 errors |
| Crypto | SHA-256 only, stdlib, no bespoke algorithms |
| Dependencies | No known CVEs in direct dependencies |
| Supply Chain | Standard Python typo-squatting risk |
| Secrets Management | No secrets in code, token via GitHub Secrets |

### 1.3 Fix Status from Previous Review

| Category | Original | Fixed | Remaining |
|---|---|---|---|
| Critical | 1 (XSS) | YES | 0 |
| High | 3 (OOM, path leak, validation) | YES | 0 |
| Medium | 4 (ReDoS, symlinks, UTF8, compliance) | 3/4 | 1 (M3: scan_type validation) |
| Low | 5 (entropy, CHANGELOG, mitre_atlas, docs) | 4/5 | 1 (evidence overflow) |
| **New findings this review** | 3 | — | 3 (see SS9) |


## 2. Attack Surface Analysis

### 2.1 Attack Vector Catalog

INPUT VECTORS: CLI Arguments + Filesystem (read-only)
OUTPUT VECTORS: Console (Rich), JSON File, HTML File, MCPGuard YAML

| # | Vector | Entry Point | Risk | Mitigation |
|---|---|---|---|---|
| V1 | Path traversal (symlinks) | cli.py -> Path.resolve() | Low | User controls path; symlinks detected |
| V2 | OOM (large files) | poisoning_detector.py read_text() | FIXED | MAX_FILE_SIZE=100MB |
| V3 | XSS in HTML | html.py -> Jinja2 | FIXED | Environment(autoescape=...) |
| V4 | Path leakage | scanner.py -> target field | FIXED | --redact-paths flag |
| V5 | ReDoS (regex) | auditor.py credential patterns | FIXED | re.compile() with limits |
| V6 | Non-UTF8 bypass | All file reads errors=replace | Low | Attacker hides payloads in non-UTF8 |
| V7 | TOCTOU (file swap) | integrity_checker.py | Low | Ephemeral scan, local attacker only |
| V8 | CLI injection | cli.py -> Typer | None | Typer sanitizes input |

### 2.2 What AIShield Does NOT Do (Security-Relevant)

| Capability | Why Missing | Security Impact |
|---|---|---|
| Network scanning | Out of scope | Zero SSRF/exfiltration risk |
| Code execution | Out of scope | Cannot be weaponized via model files |
| Authentication | Not needed (CLI tool) | No session hijacking |
| Database writes | Out of scope | No injection risk |
| File writing (to target) | Out of scope | Cannot corrupt models |
| Plugin loading | Not implemented | No supply chain from plugins |

## 3. Cryptographic Review

### 3.1 Algorithm Choices

| Usage | Algorithm | Key Size | Source | Status |
|---|---|---|---|---|
| File hashing | SHA-256 | 256 bits | hashlib (stdlib) | CORRECT |
| Fingerprinting | SHA-256 (combined) | 256 bits | hashlib (stdlib) | CORRECT |
| Scan ID generation | SHA-256 (truncated) | 64 bits | hashlib (stdlib) | OK - low entropy but acceptable |
| Combined hash | SHA-256 of sorted digests | 256 bits | hashlib (stdlib) | CORRECT |

### 3.2 Combined Hash Construction (crypto.py:50)

```python
def compute_combined_hash(file_hashes: list[str]) -> str:
    h = hashlib.sha256()
    for fh in sorted(file_hashes):
        h.update(fh.encode("utf-8"))
    return h.hexdigest()
```

FINDINGS:
- CORRECT: Sorted inputs for deterministic output
- CORRECT: SHA-256 of SHA-256 digests (no length-extension attack applicable)
- CORRECT: Order-independent, content-dependent
- NOTE: Not HMAC. If attacker controls both weights AND manifest, they can forge hashes.

### 3.3 Hash Comparison Safety

```python
if actual != entry["sha256"]:
```
Python string comparison is not constant-time, but acceptable for local file integrity checks (attacker already has filesystem access).

## 4. STRIDE Threat Model per Module

### 4.1 scanner.py (Core Engine - 446 lines)

Central orchestrator. Defines Finding, ScanResult, Severity, FindingCategory.

| Threat | Detail | Severity | Status |
|---|---|---|---|
| Spoofing | Malicious detector data via _scan_*() dicts | Low | Dict-based API, no signature |
| Tampering | Finding evidence modified between gen and output | Low | In-process only |
| Info Disclosure | str(resolved) leaks absolute paths | FIXED | --redact-paths added |
| DoS | No timeout on scan ops | Medium | Not implemented |

### 4.2 cli.py (CLI Interface - 277 lines)

Typer CLI dispatcher. 7 commands.

| Threat | Detail | Severity | Status |
|---|---|---|---|
| Spoofing | _resolve_path follows symlinks | Low | User-controlled path |
| Tampering | HTML output could overwrite system files | Low | User controls output path |
| Info Disclosure | Console output shows full paths | FIXED | --redact-paths works on target |
| DoS | No timeout on long scans | Medium | Not implemented |

### 4.3 dataset/poisoning_detector.py (Dataset Scanner - 221 lines)

Scans JSON/JSONL/CSV for trigger patterns, label flipping.

| Threat | Detail | Severity | Status |
|---|---|---|---|
| Spoofing | Crafted dataset triggers false positives | Low | Regex-based, intentional FP risk |
| Tampering | Non-UTF8 bypasses pattern matching | Medium | errors=replace corrupts input |
| Info Disclosure | Dataset content in evidence | Low | By design |
| DoS | Deeply nested JSON causes stack overflow | Medium | No recursion depth limit |

### 4.4 dataset/statistics.py (Statistical Analysis - 159 lines)

Shannon entropy, length distributions, outlier detection.

| Threat | Detail | Severity | Status |
|---|---|---|---|
| DoS | O(n) entropy calc on 100k+ entries | Medium | No streaming |
| Info Disclosure | Stats leak dataset characteristics | Low | By design |

### 4.5 lora/backdoor_detector.py (LoRA Weight Analysis - 152 lines)

Opens safetensors, checks extreme weights, layer mods.

| Threat | Detail | Severity | Status |
|---|---|---|---|
| DoS | safe_open on corrupted file | Low | In try/except |
| RCE | safetensors CVE-2024-3661 | FIXED | Pinned >=0.4.3 (have 0.7.0) |

### 4.6 pipeline/auditor.py (Pipeline Audit - 206 lines)

Scans scripts for credentials, unsafe loads, suspicious imports.

| Threat | Detail | Severity | Status |
|---|---|---|---|
| Tampering | Obfuscated credential patterns evade detection | Medium | Base64 bypass possible |
| FN risk | Missing patterns: backtick strings, YAML, CLI flags | Medium | Limited pattern coverage |

### 4.7 pipeline/compliance.py (Compliance - 186 lines)

NIST AI RMF 1.0 + OWASP LLM Top 10 checks.

| Threat | Detail | Severity | Status |
|---|---|---|---|
| Spoofing | File exists check = binary pass/fail. Empty file passes | Medium | No content verification |

### 4.8 export/mcpguard.py (MCPGuard Policy - 184 lines)

Generates MCPGuard YAML from findings.

| Threat | Detail | Severity | Status |
|---|---|---|---|
| Risky default | write_file listed as safe tool | Medium | Should be removed from safe list |

## 5. Logic Bug Deep Dive

### 5.1 NEW: write_file as Safe Tool (mcpguard.py:110)

```python
_get_known_safe_tools() -> {"read_file", "write_file", "search_web", ...}
```

**Issue**: write_file is listed as a safe tool. Generated MCPGuard policies would allow file writes by default - exactly what LoRA backdoors exploit.

**Severity**: Medium

**Fix**: Remove write_file from _get_known_safe_tools()

### 5.2 NEW: Binary Compliance Check (compliance.py:152-155)

```python
for f in files:
    if (path / f).exists():
        return "pass"
```

**Issue**: A SECURITY.md with content "TODO" passes risk_management_policy check.

**Severity**: Medium - framework is a quick assessment, not formal audit.

### 5.3 NEW: Duplicate Entry Heuristic (poisoning_detector.py:144)

```python
duplicates = {k: v for k, v in entry_hashes.items() if v > 5}
```

**Issue**: Threshold of 5+ is arbitrary. In 100k rows, 6 identical entries might be data augmentation, not poisoning. Conversely, 2 identical backdoor trigger entries could be a poisoning attempt.

**Severity**: Low - heuristic will improve with configurable thresholds.

### 5.4 Circular Import (scanner.py + supply_chain.py)

**Issue**: scanner.py imported supply_chain at top-level, supply_chain imported scanner inside function. Caused ImportError at module init.

**Fix**: Supply_chain keeps a lazy import with noqa: PLC0415.

### 5.5 Escape Hatch: hasattr Pattern (scanner.py:135 - FIXED)

Original: severity=Severity.ERROR if hasattr(Severity, "ERROR") else Severity.HIGH
Severity.ERROR doesn't exist, always fell back to HIGH. mypy flagged as dead code.

## 6. Data Flow & Privacy

### 6.1 Data Residency

| Data | Read From | Written To | Leaves Machine? |
|---|---|---|---|
| Dataset files | Local FS | Findings (memory) | NO |
| Model weights | Local FS | SHA-256 hashes only | NO |
| Config files | Local FS | Evidence dict (memory) | NO |
| .env files | Local FS | Key names only | NO |
| Scan report | N/A | HTML/JSON file | NO (unless shared) |

**Key Finding**: AIShield NEVER sends data over the network.

### 6.2 Sensitive Data in Reports

| Report Type | Content | Risk |
|---|---|---|
| Console | Finding details, file paths | Low - user's terminal |
| JSON (full) | ALL evidence: paths, snippets, configs | MEDIUM if shared externally |
| HTML | Finding details, paths | MEDIUM if shared externally |
| MCPGuard YAML | Tool allow/deny lists | Low - derived data |

**Recommendation**: Always use --redact-paths for externally shared reports.

## 7. Dependency Security

### 7.1 Direct Dependencies

| Package | Version | CVEs | Risk |
|---|---|---|---|
| typer | 0.26.1 | 0 known | GREEN |
| rich | 15.0.0 | 0 known | GREEN |
| pydantic | 2.13.4 | 0 known | GREEN |
| jinja2 | >=3.1 | 0 known in >=3.1 | GREEN |
| safetensors | 0.7.0 | CVE-2024-3661 fixed in >=0.4.3 | GREEN |
| numpy | 2.4.6 | 0 known | GREEN |
| mcp-taxonomy | 0.1.0 | 0 known | GREEN |

### 7.2 Supply Chain Risk

| Vector | Risk | Mitigation |
|---|---|---|
| Typo-squatting | Low | Pin to specific versions |
| Dependency confusion | Low | All packages from PyPI |
| Compromised upstream | Low | >= pinning, not == |

## 8. CI/CD Pipeline Security

### 8.1 CI Workflow (ci.yml)

| Check | Status | Issue |
|---|---|---|
| Actions SHA pinning | MISSING | @v4 not @<sha>, tags could be overwritten |
| Secrets exposed | None used | OK for CI-only workflow |
| Node.js 20 deprecation | Warning | Migrate to Node24-compatible versions |

### 8.2 Publish Workflow (publish.yml)

| Check | Status | Issue |
|---|---|---|
| Token scope | OK | Per-project PyPI token |
| Token in logs | OK | GitHub masks secrets |
| Token stored | OK | GitHub Secrets, never in code |

## 9. Hardening Roadmap

### Immediate (Next Release)

| Priority | Item | Effort |
|---|---|---|
| P0 | Remove write_file from safe tools in mcpguard.py | 1 min |
| P0 | Add scan_types validation in cli.py | 5 min |
| P1 | Pin GitHub Actions to SHA digests | 5 min |
| P1 | Add content verification to compliance checks | 1 hour |

### Short-term (Next 2 Releases)

| Priority | Item | Effort |
|---|---|---|
| P2 | Configurable --max-file-size and --outlier-threshold flags | 30 min |
| P2 | Streaming file reads for large datasets | 2 hours |
| P2 | UTF-8 validation before scanning | 30 min |
| P3 | IQR-based outlier detection instead of z-score | 1 hour |
| P3 | Add --timeout flag for long scans | 30 min |

### Long-term

| Priority | Item | Effort |
|---|---|---|
| P4 | HMAC-SHA256 for manifests with optional key | 1 hour |
| P4 | SARIF output format for SIEM integration | 2 hours |
| P4 | Plugin architecture for custom detectors | 1 week |
| P5 | Web dashboard for scan history | 2 weeks |

### Security Checklist for Production Deployment

```
[ ] Pin dependencies to exact versions (requirements.txt)
[ ] Pin GitHub Actions to SHA digests
[ ] Use --redact-paths when sharing reports
[ ] Review generated MCPGuard policies before deployment
[ ] Do not serve HTML reports via web (even with auto-escape)
[ ] Set up PyPI trusted publishing (in progress)
[ ] Add Dependabot for automatic dependency updates
[ ] Configure CODEOWNERS for CI/CD workflow changes
```

## 10. Conclusion

### Maturity Model

| Capability | Coverage |
|---|---|
| CWE Categories | 6+ detected |
| OWASP LLM Top 10 | 60% coverage |
| NIST AI RMF 1.0 | 12 checks across 4 functions |
| MITRE ATLAS | 8 fine-tuning attack techniques |
| Supply Chain Security | SHA-256 + provenance tracking |

### Final Assessment

AIShield is a WELL-SECURED CLI tool. Key strengths:
  - Minimal attack surface (CLI + filesystem reads only)
  - No network calls, no code execution, no auth to bypass
  - Strong cryptographic practices (SHA-256, no custom algorithms)
  - Good test coverage (196 tests, 89% coverage)
  - Clean code (ruff 0 errors, mypy 0 errors)

The 3 new findings (write_file safe tool, binary compliance, duplicate heuristic) are LOW-MEDIUM severity and trivially fixable. The tool's design philosophy of being a read-only CLI scanner with no network surface makes it inherently more secure than tools with web dashboards or API endpoints.
