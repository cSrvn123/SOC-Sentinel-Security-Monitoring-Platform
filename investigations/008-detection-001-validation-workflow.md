# SOC Sentinel Stage 8 — Detection 001 Validation Workflow

**Purpose:** document the local structural and synthetic validation workflow for Detection 001.

**Rule:** `100100`  
**Configured level:** `10`  
**Deployment state:** draft; undeployed  
**Wazuh rule-engine status:** **NOT_RUN**

> **Platform requirement:** Stage 8 structural XML validation currently requires Windows because its path-safety checks fail closed on unsupported platforms. This requirement applies to that validation workflow; it does not imply that every SOC Sentinel package requires Windows. No general cross-platform compatibility claim is made.

## Executive Summary

Stage 8 provides a repeatable local workflow for checking the structure of the Detection 001 XML and comparing its documented synthetic cases with a deliberately limited Python regular-expression approximation. The workflow loads the case manifest, structurally validates the actual XML, runs the approximation only after structural validation passes, then renders JSON and Markdown from the resulting report model.

The observed result was **40 of 40 expected comparisons passing in the Python approximation**. This result says only that the Python approximation agreed with the manifest expectations for those synthetic inputs. It does not prove that Wazuh loads the rule, that a decoder assigns the supplied group, that PCRE2 behaves identically, or that the rule fires in a Wazuh manager.

No real malicious activity was executed. Manifest command-line values, including `SYNTHETIC-TEST-DATA`, were treated as inert strings. No payload was decoded, no PowerShell was launched, no external service was contacted, and no rule was deployed.

## Validation Workflow

The public APIs are called in this order:

1. `load_manifest()` reads and validates the local JSON manifest, preserving its case order and freezing event mappings and sequences.
2. `validate_detection_001_xml()` parses the local XML and checks the exact supported Detection 001 structure.
3. `run_manifest_approximation()` requires successful structural validation and freshly validates the bounded XML bytes it uses. It evaluates each case with the Python `re` implementation and supplied group metadata.
4. `format_json()` serializes the report model, including synthetic event data and per-case results.
5. `format_markdown()` creates an analyst-readable summary without expanding raw event records or command lines.

These are distinct validation layers. A structural `PASS` means the XML syntax and supported structure passed the local contract. An approximation case `PASS` means the Python approximation agreed with that case's expected outcome. Neither status is an overall Wazuh validation result.

## Rule Under Test

The inspected XML declares rule ID `100100`, level `10`, parent group `sysmon_event1`, and two field conditions:

- `win.eventdata.image` must match a case-insensitive PowerShell or PowerShell 7 executable image ending in `powershell.exe` or `pwsh.exe`.
- `win.eventdata.commandLine` must begin with an executable token, may include the supported launcher options, and must then contain the exact `-EncodedCommand` or `-enc` option with an argument boundary.

The XML also contains a descriptive string, the ATT&CK identifier `T1059.001`, and the rule group `powershell,process_creation,`.

The manifest's synthetic records include `win.system.eventID=1`, but the Python runner evaluates the explicit `if_group=sysmon_event1` condition as supplied group metadata and the two extracted field expressions. It does not independently establish Windows Event ID semantics or decoder behavior. The group label in each fixture is test input, not evidence of real Wazuh decoder assignment.

## Synthetic Case Set and Results

The manifest contains 40 unique cases in this order: P1–P6, N1–N6, FP1–FP3, L1–L11, V1–V6, M1–M3, N7–N9, and I1–I2. Categories and results were:

| Category | Cases | Expected/observed result | Python comparison |
|---|---:|---|---:|
| Positive | 27 | Match | 27/27 pass |
| Negative | 10 | No match | 10/10 pass |
| False-positive context | 3 | Match; analyst review required | 3/3 pass |
| **Total** | **40** | All manifest cases received a result | **40/40 pass** |

False-positive-context cases are deliberately expected alerts where the rule conditions match. Their context is for analyst review; it is not a suppression instruction. The case set covers positive invocations, negative conditions, supported launcher options, quoting/casing/spacing variations, Image/command-line mismatches, invocation attempts without values, and authorized-activity contexts. A switch with no following value is treated as an invocation attempt, not proof that a valid command ran.

The actual public file workflow rejects changed or unsupported rule expressions during structural validation (`FAIL` for a valid but unsupported structure, or `ERROR` for malformed XML) and returns explicit `NOT_RUN` approximation results. It does not pass those altered XML expressions through the approximation compiler. Separate unit tests exercise the compiler's malformed-pattern error directly, and an isolated runner-branch test bypasses the normal structural prerequisite to verify `UNSUPPORTED` mapping. Those are branch-level tests, not evidence that malformed or unsupported XML traversed the actual public workflow. Missing approximation results are also represented explicitly; none of these states is converted to a successful comparison.

## Structural XML Validation

The structural validator accepts only the inspected Detection 001 XML contract, including the expected root/rule hierarchy, rule ID and level, required group, exact fields and regex attributes/expressions, supported child ordering, descriptive metadata, ATT&CK ID, and rule group. Malformed/unreadable input returns structural `ERROR`; valid but mismatched or unsupported structure returns `FAIL`; only the supported structure returns `PASS`.

Path checks are local and read-only. On Windows, the validator checks drive type and path components for reparse points before opening and performs a bounded read. This check is not atomic with the subsequent open: a concurrent path replacement can create a time-of-check/time-of-use (TOCTOU) race. The validator does not claim race-free path security. It fails closed on platforms where its Windows path-safety checks are unavailable.

The child ordering restriction is the validator's supported-structure contract. It is not evidence about Wazuh's parser ordering semantics.

## Python Expression Approximation

The runner extracts expressions from the structurally validated XML and uses Python's standard `re` module over inert synthetic strings. It rejects syntax outside its narrow, documented subset rather than translating unsupported constructs.

**Python `re` is not PCRE2.** Python approximation results are not Wazuh regex results and do not prove that the Wazuh engine accepts or interprets the expressions identically. Supplied synthetic group metadata does not prove that a real decoder assigns `sysmon_event1`.

The manifest input and recursively immutable synthetic event data are not modified. The runner does not decode payloads, execute command lines, launch PowerShell, make network requests, call VirusTotal, deploy rules, or invoke `wazuh-logtest`.

## JSON and Markdown Reports

Both formatters operate only on the supplied `ValidationReport`; they do not reload the manifest, reread XML, rerun regexes, or contact Wazuh.

- JSON preserves the rule metadata, structural result, all cases and synthetic event fields, approximation results, category/status counts, limitations, deployment note, and Wazuh status. Output is deterministic and valid JSON. JSON contains synthetic command-line fields and should be reviewed before sharing; real-world validation data could contain sensitive log information.
- Markdown reports rule metadata, structural and approximation status, category counts, per-case expected/observed results, false-positive context, unsupported/error/not-run cases, deployment status, Wazuh status, and limitations. It escapes dynamic Markdown/HTML-sensitive text and omits raw event records and command lines.

There is no combined status that turns structural and Python comparison passes into a Wazuh pass. The current report records deployment as not performed and Wazuh engine status as `NOT_RUN`.

## Analyst Interpretation

The 40 cases are synthetic validation examples, not confirmed attacks or benign endpoint events. A passing positive case checks that its expected input matched the approximation; a passing negative case checks that its expected input did not match. False-positive-context matches demonstrate why an alert may still need contextual review. They do not say that the activity is malicious, nor that the alert should be suppressed.

All 40 Python approximation comparisons passed in the local run. **No live Wazuh manager or rule-engine validation occurred.** No claim is made that this rule has been validated in Wazuh 4.14.1.

## Deployment and Genuine Wazuh Validation

Detection 001 remains a draft and undeployed. Genuine Wazuh 4.14.1 rule-engine validation would require a safe, isolated environment running that version with the relevant manager ruleset and decoder configuration. The analyst would need to load the rule only in that test environment, submit properly formatted synthetic events through `wazuh-logtest`, record the exact Wazuh version and decoded fields, and compare each engine result with the manifest. That work has not been performed here. The current report's Wazuh status remains **NOT_RUN**.

## Scope and Safety Boundaries

- All case events and values are synthetic.
- Command-line strings are data for matching only; none were executed or decoded.
- No malware, real attack, scan, live endpoint event, or production security data was used.
- No external lookup, VirusTotal request, network request, rule deployment, or automated response was performed.
- Structural validation and Python approximation are local checks only; they do not replace Wazuh 4.14.1 rule-engine testing.
