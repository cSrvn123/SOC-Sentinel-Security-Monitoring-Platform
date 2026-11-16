# SOC Sentinel Publication Checklist

This is a proposed inclusion checklist based on the previously reviewed publication manifest. It records publication recommendations only; no files have been staged or published. Review the final Git diff and status before any GitHub action.

## Proposed disposition

| Disposition | Count from the approved manifest | Guidance |
|---|---:|---|
| Include | 63 | Source, tests, documentation, synthetic fixtures, and the approved Stage 7 gallery/report Markdown listed below. |
| Hold | 2 | Keep the Stage 7 JSON report and exporter out of the publication set until their specific review/limitations are resolved. |
| Exclude | 2 | Do not publish the duplicate screenshot archive or the separate executive-summary screenshot. |

These counts preserve the original 67-entry manifest exactly. The four additional preparation files, three investigation worksheets, and five reviewed files in the following sections are outside the original manifest and are not included in its counts. The proposed Include total is 75: 63 original Include paths plus 12 separately accounted additional Include files. `README.md` remains one of the original 67 entries; its latest approved update adds a link to `LICENSE` without adding another manifest path.

## Additional preparation files (4) — outside the original manifest

| Path | Current status | Proposed disposition | Condition or reason |
|---|---|---|---|
| `architecture/architecture.md` | Modified tracked file | **INCLUDE** | Keep the prominent design-context disclaimer and link to `docs/ARCHITECTURE.md`. This path was modified after the original 67-entry manifest and is not part of its counts. |
| `requirements.txt` | Modified tracked file | **INCLUDE** | Describes the current standard-library-only documented workflows; adds no third-party dependencies. This path is additional to the original manifest. |
| `docs/PUBLICATION-CHECKLIST.md` | New untracked file | **INCLUDE** | Publication-preparation checklist. This file is additional to the original manifest and does not alter its counts. |
| `LICENSE` | New untracked file | **INCLUDE** | Complete Apache License 2.0 text with copyright notice `Saravana C`. The README links to this root-level license. This path is additional to the original manifest. |

## Additional investigation worksheets (3) — outside the original manifest

| Path | Current status | Proposed disposition | Condition or reason |
|---|---|---|---|
| `investigations/authentication-investigation.md` | Modified tracked file | **INCLUDE** | Manually completed authentication investigation template; not automated SOC Sentinel output. This path is additional to the original manifest. |
| `investigations/process-investigation.md` | Modified tracked file | **INCLUDE** | Manually completed process investigation template; not automated SOC Sentinel output. This path is additional to the original manifest. |
| `investigations/network-investigation.md` | Modified tracked file | **INCLUDE** | Manually completed network investigation template; not automated SOC Sentinel output. This path is additional to the original manifest. |

## Additional reviewed files (5) — outside the original manifest

| Path | Current status | Proposed disposition | Condition or reason |
|---|---|---|---|
| `detections/authentication.md` | Modified tracked file | **INCLUDE** | Documents future authentication detection plans, distinct from existing supplied-event analysis and correlation. This path is additional to the original manifest. |
| `detections/network-monitoring.md` | Modified tracked file | **INCLUDE** | Documents future network detection plans and the current Event ID 3/22 and IOC limitations. This path is additional to the original manifest. |
| `detections/process-monitoring.md` | Modified tracked file | **INCLUDE** | Documents broader future process detections, distinct from Detection 001. This path is additional to the original manifest. |
| `sysmon/configuration/README.md` | Modified tracked file | **INCLUDE** | Documents the minimal Sysmon sample, capture scope, privacy implications, and unvalidated status. This path is additional to the original manifest. |
| `sysmon/configuration/sysmonconfig.xml` | Modified tracked file | **INCLUDE** | Minimal illustrative Sysmon XML sample; it is not deployed or validated. This path is additional to the original manifest. |

## Separate disposition for an unchanged remote file — outside the original manifest

| Path | Proposed disposition | Condition or reason |
|---|---|---|
| `tools/sysmon/Eula.txt` | **EXCLUDE** | Third-party Sysinternals license terms are not needed to describe or run this project, which does not include a Sysinternals executable. The file has been removed from the current working tree and is excluded from the proposed publication candidate. Its original version remains in existing Git history; no history rewrite or force-push is planned. This separate disposition is outside the original 67-entry manifest and 12 additional Include files, so the original counts remain unchanged. |

## Include — proposed

### Project documentation and Detection 001 materials

- [ ] `README.md` — project overview, setup, workflows, scope, limitations, and a link to the root `LICENSE`.
- [ ] `detections/001-suspicious-powershell-encoded-command.md` — Detection 001 rationale.
- [ ] `python/README.md` — Python package usage and privacy guidance.
- [ ] `tests/detection-001-suspicious-powershell-encoded-command.md` — 40-case synthetic test plan.
- [ ] `wazuh/custom-rules/100100-suspicious-powershell.xml` — draft rule; label as undeployed and unvalidated.
- [ ] `docs/ARCHITECTURE.md` — architecture of the implemented local workflows.
- [ ] `docs/STAGE7-DEMO.md` — Stage 7 synthetic screenshot gallery.
- [ ] `investigations/007-suspicious-powershell-case-study.md` — synthetic investigation case study.
- [ ] `investigations/008-detection-001-validation-workflow.md` — local Stage 8 workflow and its limitations.

### Python packages

- [ ] `python/alert_correlation/__init__.py`
- [ ] `python/alert_correlation/engine.py`
- [ ] `python/alert_correlation/formatting.py`
- [ ] `python/alert_correlation/models.py`
- [ ] `python/detection_validation/__init__.py`
- [ ] `python/detection_validation/formatting.py`
- [ ] `python/detection_validation/loader.py`
- [ ] `python/detection_validation/models.py`
- [ ] `python/detection_validation/runner.py`
- [ ] `python/incident_reporting/__init__.py`
- [ ] `python/incident_reporting/attack_mapping.py`
- [ ] `python/incident_reporting/builder.py`
- [ ] `python/incident_reporting/formatting.py`
- [ ] `python/incident_reporting/models.py`
- [ ] `python/incident_reporting/timeline.py`
- [ ] `python/ioc_enrichment/__init__.py`
- [ ] `python/ioc_enrichment/classification.py`
- [ ] `python/ioc_enrichment/cli.py`
- [ ] `python/ioc_enrichment/enrichment.py`
- [ ] `python/ioc_enrichment/formatting.py`
- [ ] `python/ioc_enrichment/models.py`
- [ ] `python/ioc_enrichment/reputation.py`
- [ ] `python/ioc_enrichment/validation.py`
- [ ] `python/windows_event_analyzer/__init__.py`
- [ ] `python/windows_event_analyzer/analyzer.py`
- [ ] `python/windows_event_analyzer/cli.py`
- [ ] `python/windows_event_analyzer/examples/synthetic_events.json`
- [ ] `python/windows_event_analyzer/formatting.py`
- [ ] `python/windows_event_analyzer/models.py`

### Tests and synthetic validation data

- [ ] `python/tests/__init__.py`
- [ ] `python/tests/test_alert_correlation.py`
- [ ] `python/tests/test_detection_validation.py`
- [ ] `python/tests/test_end_to_end_incident_scenarios.py`
- [ ] `python/tests/test_incident_reporting.py`
- [ ] `python/tests/test_incident_reporting_attack_mapping.py`
- [ ] `python/tests/test_incident_reporting_formatting.py`
- [ ] `python/tests/test_incident_reporting_timeline.py`
- [ ] `python/tests/test_ioc_enrichment.py`
- [ ] `python/tests/test_stage7_soc_investigation.py`
- [ ] `python/tests/test_stage8_detection_validation_workflow.py`
- [ ] `python/tests/test_windows_event_analyzer.py`
- [ ] `tests/fixtures/detection-001-cases.json` — synthetic manifest; do not execute its command-line strings.

### Synthetic portfolio outputs and gallery images

- [ ] `reports/stage-007/STAGE7-SYNTHETIC-001.md` — synthetic report summary with the approved PID clarification and duplicate ATT&CK reference removed.
- [ ] `screenshots/stage7-screenshots-edited/stage7-section-01.png`
- [ ] `screenshots/stage7-screenshots-edited/stage7-section-02.png`
- [ ] `screenshots/stage7-screenshots-edited/stage7-section-03.png`
- [ ] `screenshots/stage7-screenshots-edited/stage7-section-04.png`
- [ ] `screenshots/stage7-screenshots-edited/stage7-section-05.png`
- [ ] `screenshots/stage7-screenshots-edited/stage7-section-06.png`
- [ ] `screenshots/stage7-screenshots-edited/stage7-section-07.png`
- [ ] `screenshots/stage7-screenshots-edited/stage7-section-08.png`
- [ ] `screenshots/stage7-screenshots-edited/stage7-section-09.png`
- [ ] `screenshots/stage7-screenshots-edited/stage7-section-10.png`
- [ ] `screenshots/stage7-screenshots-edited/stage7-section-11.png`

## Hold — do not publish yet

- [ ] `reports/stage-007/STAGE7-SYNTHETIC-001.json` — HOLD pending a specific publication-safety review of the serialized evidence and confirmation that the report contains only intended synthetic content. JSON exports can preserve raw records and may expose sensitive data in real investigations.
- [ ] `tools/export_stage7_reports.py` — HOLD. The exporter depends on a private Stage 7 test helper and currently refuses to run when its output directory already exists. Do not advertise or include it until those limitations are explicitly resolved and reviewed.

## Exclude

- [ ] `screenshots/stage7-screenshots-edited.zip` — duplicate archive of the individual gallery images; publish the PNGs instead.
- [ ] `screenshots/stage-007-executive-summary.png` — separate screenshot is redundant with the approved 11-image gallery and includes extra editor interface content.

## Final pre-publication checks

- [ ] Re-run the documented Python test suite from `python/` and record the result for the exact candidate revision.
- [ ] Check that all relative Markdown links and gallery image paths resolve in the candidate tree.
- [ ] Review all JSON and report outputs for privacy. Synthetic labels do not by themselves prove that a file contains no accidental real data.
- [ ] Confirm no credentials, tokens, private endpoint records, or locally collected telemetry are included.
- [ ] Keep Detection 001 identified as a draft and undeployed; Wazuh rule-engine validation remains `NOT_RUN`.
- [ ] Keep the Stage 8 Python regular-expression approximation distinct from PCRE2 and Wazuh validation.
- [ ] Confirm `.gitignore` still excludes local artifacts and that no ignored local files are force-added.
- [ ] Confirm the exact publication candidate and obtain explicit approval before staging, committing, pushing, or publishing. No publication has occurred.
