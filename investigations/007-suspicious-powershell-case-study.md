# Stage 7 — Suspicious PowerShell Process Execution with Network and DNS Indicators

**Case classification:** Synthetic SOC analyst training exercise
**Case ID:** `STAGE7-SYNTHETIC-001`
**Environment:** `SOC-LAB-01`
**Account:** `SYNTHETIC\analyst.demo`

## Executive Summary

This case study walks through a synthetic Windows investigation involving repeated failed logons, a successful logon, a PowerShell process in a user-writable path, and nearby Sysmon network and DNS events. The IP address, domain, process hash, event records, account, and host are test data.

The analyzer and correlation engine produce investigation prompts and four separate correlation cases. A test-only analyst composition helper groups those cases for this training report; the correlation engine does not automatically merge them. The training assessment is **SUSPICIOUS**, severity is **MEDIUM**, and correlation confidence remains **medium**. These are separate fields with separate rationales.

**This is not a live Wazuh alert or endpoint investigation.** No live Wazuh Manager received an alert, Detection 001 remains a draft, and no running Wazuh Manager or Wazuh rule engine validated that rule. No command or payload was executed. IOC results are synthetic offline fixtures, not threat intelligence.

## Case Classification and Scope

- Data source: inline synthetic Windows Security and Sysmon event records.
- Processing: existing Windows Event Analyzer, IOC Enrichment, Alert Correlation, and Incident Reporting APIs.
- IOC provider: explicitly supplied `OfflineReputationProvider` only.
- External lookups, VirusTotal requests, scans, active response, and live endpoint access: none.
- The target address `203.0.113.66` and `192.0.2.25` are documentation-only IP addresses. `203.0.113.66` is not globally routable. `suspicious.example` is a reserved example domain.

## Initial Alert and Triage

The exercise begins with a **synthetic case briefing**: review a Sysmon Event ID 1 record containing PowerShell in a user-writable path and an inert `-EncodedCommand SYNTHETIC-TEST-DATA` string. The briefing is a scenario premise, not a Wazuh alert emitted by this project. The test confirms that the analyzer flags the writable path but does not implement an encoded-command heuristic.

The existing Detection 001 documentation describes intended Wazuh rule behavior and says it is a draft. It is not evidence that rule ID 100100 fired in this exercise.

## Host and User Context

The event set uses host `SOC-LAB-01` and account `SYNTHETIC\analyst.demo`. Three Security Event ID 4625 records share that account, host, and documentation source IP, followed by Event ID 4624. A separate successful logon for `SYNTHETIC\service.demo` is included as unrelated activity and is not included in the incident timeline.

The analyzer normalizes the supported event IDs and preserves original input records. It does not resolve account ownership, host role, privilege, or business purpose; those require analyst-supplied context.

## Process Investigation

The target Sysmon Event ID 1 record contains:

| Field | Synthetic value |
|---|---|
| Image | `C:\Users\SYNTHETIC\analyst.demo\AppData\Local\Temp\powershell.exe` |
| Process ID | `6684` |
| Process GUID | `{22222222-2222-4222-8222-222222222222}` |
| Command line | `powershell.exe -NoProfile -EncodedCommand SYNTHETIC-TEST-DATA` |
| Hashes | `SHA256=` followed by 64 synthetic `A` characters |

The analyzer normalizes image/path, process ID, command line, parent image, user, and event timestamp. It does **not** normalize hashes, ProcessGuid, or ParentProcessGuid into `NormalizedEvent`; those values remain in the preserved raw Event ID 1 record and incident provenance. The test explicitly extracts the synthetic SHA-256 from that raw record and passes it to offline enrichment. The hash result is a synthetic unknown fallback.

The writable-path observation is a heuristic. It does not establish that the executable is malicious, that a payload ran, or that the user intended harmful activity.

## Parent-Child Process Investigation

The raw records contain a synthetic `explorer.exe` process (PID `1000`) and the PowerShell event’s `ParentImage`, `ParentProcessId`, and `ParentProcessGuid`. The values are consistent with a parent-child relationship in the fixture.

The correlator can add a matching parent-image process event based on same-host image-path and time context. It expressly treats that as contextual evidence and reports that process lineage is not confirmed. The project does not verify PID or ProcessGuid linkage as a lineage rule. This report therefore records the field comparison as an **analyst hypothesis**, not a verified process tree.

## Command-Line Analysis

The command-line value is inert test data and was never executed. The analyzer does not detect `-EncodedCommand` by itself. In the integration test, a normal System32 PowerShell path with encoded-command text alone produces no analyzer observation and no correlation case.

Encoding can conceal script contents, but this exercise does not decode or execute a payload. The string is not proof of execution, intent, or compromise.

## Network Investigation

Sysmon Event ID 3 has destination `203.0.113.66`, protocol `tcp`, destination port `443`, source `192.0.2.25`, and process image/PID fields that match the synthetic PowerShell event. The analyzer normalizes the address and process fields; protocol and ports remain in raw evidence.

The destination is documentation-only address space, not a real globally routable threat destination. The correlation case is created because the event destination exactly matches a supplied valid IOC result. The engine does not join Event ID 3 to Event ID 1 by PID or ProcessGuid. The same PID/image fields are an analyst-created association hypothesis for this scenario, not an engine-established process ownership link.

## DNS Investigation

Sysmon Event ID 22 records `suspicious.example`, with synthetic process fields and a raw query-results value. The analyzer normalizes the query name and available common process fields. It does not normalize query results or establish that the query resolved to the Event ID 3 destination.

The DNS correlation is a separate exact query-to-supplied-IOC association. Shared process fields and close timestamps provide context for analyst review, not proof that the same process caused both events.

## IOC Enrichment

The test extracts three indicators explicitly and calls `enrich_indicator()` with `OfflineReputationProvider`:

| Indicator | Synthetic result | Interpretation |
|---|---|---|
| `203.0.113.66` | `synthetic_suspicious` | Offline fixture only; documentation address, not a live threat reputation |
| `suspicious.example` | `synthetic_suspicious` | Offline fixture only; reserved example domain |
| Synthetic SHA-256 | `synthetic_unknown` | Offline fallback; no hash reputation lookup was performed |

The status and risk labels are example fixture outputs, not verified intelligence. The correlation engine consumes supplied results; it performs no enrichment or network request. No indicator was sent to VirusTotal.

## Timeline of Events

All fixture timestamps contain an explicit UTC offset. The incident timeline is built only from the curated incident’s related events. The unrelated notepad process (record `7201`) and service-account logon (record `7010`) remain outside it.

| UTC time | Source / event | Record | Summary |
|---|---|---:|---|
| 09:58:10 | Security 4625 | 7001 | Failed logon for synthetic analyst account |
| 09:58:20 | Security 4625 | 7002 | Failed logon for same synthetic account and source |
| 09:58:30 | Security 4625 | 7003 | Failed logon for same synthetic account and source |
| 10:00:00 | Security 4624 | 7004 | Successful logon for same account and source |
| 10:00:30 | Sysmon 1 | 7100 | Synthetic `explorer.exe` process record; parent context only |
| 10:02:00 | Sysmon 1 | 7101 | PowerShell process in a user-writable path |
| 10:02:40 | Sysmon 22 | 7102 | Query for `suspicious.example` |
| 10:03:00 | Sysmon 3 | 7103 | Connection to documentation address `203.0.113.66` |

The timeline preserves the original timestamp values, related-event indices, source references, and matched provenance status. Timestamps show order, not causality.

## Correlation Findings

The existing engine emits four separate **medium-confidence** cases:

1. Repeated failed logons followed by successful logon: same host/account/source and configured threshold/window.
2. Successful logon followed by unusual process creation: host/account/time alignment and the analyzer’s writable-path observation; parent image matching remains contextual.
3. Network connection associated with an available IOC result: Event ID 3 destination matches the supplied synthetic IP result.
4. DNS query associated with an available IOC result: Event ID 22 query matches the supplied synthetic domain result.

The test-only analyst composition combines the four cases after checking that component cases refer to the same input batch and that source references do not conflict. It preserves the component evidence, missing-evidence statements, recommendations, source records, and report diagnostics. This grouping is not an automatic correlation-engine feature. Confidence is copied; it is not raised by the number of cases or IOC results.

## Evidence and Provenance

- Original input records remain at collection level; associated original records and source references remain available through incident provenance.
- Each timeline entry maps to one incident-related event index. Unrelated events do not enter the incident timeline.
- The test checks that process IDs, GUID fields, command line, hash, ports, protocol, and DNS query-results remain in raw source evidence where the analyzer does not normalize them.
- Network and DNS component cases each contain their own event. They are not silently joined to the process event by the correlation engine.
- JSON exports retain raw source records and may contain sensitive data in real use. Review JSON before sharing. Markdown provides concise evidence/provenance summaries and does not expand raw event records by default.

## False-Positive Assessment

Legitimate endpoint administration, deployment automation, troubleshooting, or approved security exercises may use PowerShell, writable staging paths, encoded command-line arguments, and network/DNS activity. Repeated authentication failures may be user error or expected automation. Synthetic IOC fixture labels do not reduce those possibilities.

The analyst should validate account ownership, host role, change/deployment records, executable provenance, process context, network purpose, and independent indicator context before escalating beyond this training assessment.

## Severity Assessment

**Severity: MEDIUM** — explicit synthetic analyst assessment, not an engine output. The written rationale is that several related suspicious signals on one synthetic host justify triage priority, while no confirmed impact, data loss, persistence, or critical-asset context is available. Severity is impact/urgency; it is not the correlation-confidence value.

## Analyst Conclusion

**Conclusion: SUSPICIOUS** — explicit synthetic analyst assessment. The writable-path process event and associated synthetic IOC matches warrant further review. The inert command-line string, synthetic reputation labels, and matching event fields do not prove payload execution, process ownership, or malicious intent. Correlation confidence remains **medium** and is not the conclusion.

## MITRE ATT&CK Mapping

- **T1059.001 — PowerShell**: explicitly supplied for the related Sysmon Event ID 1 process event.
- **Reference status: UNVERIFIED**. The mapping helper checks identifier syntax but this project has no pinned local ATT&CK catalogue. The mapping is not an official verification or a maliciousness verdict.

## Missing Evidence and Limitations

- No verified payload analysis; the command line is an inert synthetic string.
- No dedicated validation of PID/ProcessGuid process lineage.
- No engine-established link from Event ID 3 or 22 to the Event ID 1 process.
- No independently verified threat-intelligence reputation or IOC observation timestamp.
- No live endpoint investigation, Wazuh Manager alert, or Wazuh rule-engine validation.
- No host asset criticality, account-owner confirmation, change record, or confirmed business impact.
- Hashes, network ports/protocol, and richer DNS fields are preserved raw but are not all normalized by the analyzer.

## Recommended Next Investigation Steps

1. In a real authorized environment, verify the alert and source records in the operational SIEM; do not infer that this draft rule fired.
2. Confirm host role, account owner, logon type, and approved change/deployment activity.
3. Review the raw process record and validate image, command line, hash, parent fields, and process identifiers using authorized endpoint evidence.
4. Validate network and DNS events independently, including destination purpose, ports/protocol, resolver results, and actual process ownership.
5. Use only approved, privacy-reviewed intelligence sources; record source and observation time and do not disclose sensitive indicators without authorization.
6. Reassess severity and conclusion separately as evidence changes, preserving missing evidence and provenance.

No automated blocking, process termination, account disabling, or other response action is performed by this demonstration.
