# SOC Sentinel Incident Report Collection

## Collection Summary
- Schema version: 1\.0
- Incidents: 1
- Original input records: 10 (kept at collection level)
- Source batches: 1

## Collection Diagnostics
- None recorded.

## Skipped Events
- None recorded.

Collection-level records, diagnostics, and skipped events are not incident-specific evidence.

---

## Incident Summary: INC\-STAGE7\-SYNTHETIC\-001
- Title: Analyst\-curated suspicious PowerShell investigation
- Source case: STAGE7\-SYNTHETIC\-001
- Schema version: 1\.0
- Entities: accounts=SYNTHETIC\\analyst\.demo; computers=SOC\-LAB\-01; IPs=192\.0\.2\.25, 203\.0\.113\.66

### Correlation Confidence
- Confidence: medium
- Explanation: Copied from four medium\-confidence component correlations; the analyst composition does not increase correlation confidence\.
Confidence describes correlation strength only; it is not incident severity or proof of compromise.

### Severity Assessment
- Severity: MEDIUM
Severity is the analyst-assessed impact and urgency; it is separate from correlation confidence.

### Analyst Conclusion
- Conclusion: SUSPICIOUS
A suspicious or inconclusive conclusion is not a confirmed-malicious finding.

### Severity Rationale
Analyst\-selected medium triage urgency for several related suspicious signals on one synthetic host; no confirmed impact, data loss, persistence, or critical\-asset context is present\.

### Analyst Conclusion Rationale
The synthetic process event uses a writable path and is followed by matching synthetic network and DNS indicator associations\. These signals justify continued investigation, but synthetic reputation, an encoded\-command string, and event\-field matches do not prove payload execution or malicious intent\.

### Timeline
- Related event 0 (valid): 2026\-04\-07T09:58:10\+00:00 — Windows Security Event ID 4625 Failed logon; normalized UTC: 2026\-04\-07T09:58:10\+00:00
  - Source references: source\_record:\[&quot;windows security&quot;,&quot;soc\-lab\-01&quot;,&quot;security&quot;,&quot;7001&quot;\]
  - Provenance: matched
- Related event 1 (valid): 2026\-04\-07T09:58:20\+00:00 — Windows Security Event ID 4625 Failed logon; normalized UTC: 2026\-04\-07T09:58:20\+00:00
  - Source references: source\_record:\[&quot;windows security&quot;,&quot;soc\-lab\-01&quot;,&quot;security&quot;,&quot;7002&quot;\]
  - Provenance: matched
- Related event 2 (valid): 2026\-04\-07T09:58:30\+00:00 — Windows Security Event ID 4625 Failed logon; normalized UTC: 2026\-04\-07T09:58:30\+00:00
  - Source references: source\_record:\[&quot;windows security&quot;,&quot;soc\-lab\-01&quot;,&quot;security&quot;,&quot;7003&quot;\]
  - Provenance: matched
- Related event 3 (valid): 2026\-04\-07T10:00:00\+00:00 — Windows Security Event ID 4624 Successful logon; normalized UTC: 2026\-04\-07T10:00:00\+00:00
  - Source references: source\_record:\[&quot;windows security&quot;,&quot;soc\-lab\-01&quot;,&quot;security&quot;,&quot;7004&quot;\]
  - Provenance: matched
- Related event 4 (valid): 2026\-04\-07T10:00:30\+00:00 — Sysmon Event ID 1 Process creation; normalized UTC: 2026\-04\-07T10:00:30\+00:00
  - Source references: source\_record:\[&quot;sysmon&quot;,&quot;soc\-lab\-01&quot;,&quot;microsoft\-windows\-sysmon/operational&quot;,&quot;7100&quot;\]
  - Provenance: matched
- Related event 5 (valid): 2026\-04\-07T10:02:00\+00:00 — Sysmon Event ID 1 Process creation; normalized UTC: 2026\-04\-07T10:02:00\+00:00
  - Source references: source\_record:\[&quot;sysmon&quot;,&quot;soc\-lab\-01&quot;,&quot;microsoft\-windows\-sysmon/operational&quot;,&quot;7101&quot;\]
  - Provenance: matched
- Related event 6 (valid): 2026\-04\-07T10:02:40\+00:00 — Sysmon Event ID 22 DNS query; normalized UTC: 2026\-04\-07T10:02:40\+00:00
  - Source references: source\_record:\[&quot;sysmon&quot;,&quot;soc\-lab\-01&quot;,&quot;microsoft\-windows\-sysmon/operational&quot;,&quot;7102&quot;\]
  - Provenance: matched
- Related event 7 (valid): 2026\-04\-07T10:03:00\+00:00 — Sysmon Event ID 3 Network connection; normalized UTC: 2026\-04\-07T10:03:00\+00:00
  - Source references: source\_record:\[&quot;sysmon&quot;,&quot;soc\-lab\-01&quot;,&quot;microsoft\-windows\-sysmon/operational&quot;,&quot;7103&quot;\]
  - Provenance: matched

### Evidence
- 3 distinct Event ID 4625 records for the same computer/account/source IP precede Event ID 4624 within 600 seconds\.
- Event ID 4624 and Event ID 1 share the computer/account and occur in order within the configured window\.
- Process image is under a commonly user\-writable location; verify expected software and launch context\.
- A separate Sysmon process event has a matching parent image on the same computer and within the configured time window; this is contextual evidence only, not confirmed process lineage\.
- PowerShell child process PID: 6684; parent Explorer process PID: 1000; parent image/path: C:\\Windows\\explorer\.exe (matching synthetic parent fields; process lineage is not independently verified)\.
- Sysmon Event ID 3 destination IP exactly matches supplied, validated IOC 203\.0\.113\.66\.
- Supplied IOC result for 203\.0\.113\.66: \{&quot;error&quot;:null,&quot;harmless&quot;:0,&quot;indicator&quot;:&quot;203\.0\.113\.66&quot;,&quot;indicator\_type&quot;:&quot;IPv4&quot;,&quot;investigation\_recommendation&quot;:&quot;Synthetic example only: investigate related activity and corroborate evidence\.&quot;,&quot;malicious&quot;:0,&quot;reputation\_status&quot;:&quot;synthetic\_suspicious&quot;,&quot;risk\_classification&quot;:&quot;elevated&quot;,&quot;source&quot;:&quot;Synthetic offline fixture&quot;,&quot;suspicious&quot;:2,&quot;validation\_reason&quot;:&quot;Valid IP address syntax\.&quot;,&quot;validation\_status&quot;:&quot;valid&quot;\}
- No lookup was performed by the correlation engine\.
- Sysmon Event ID 22 query exactly matches supplied, validated IOC suspicious\.example\.
- Supplied IOC result for suspicious\.example: \{&quot;error&quot;:null,&quot;harmless&quot;:0,&quot;indicator&quot;:&quot;suspicious\.example&quot;,&quot;indicator\_type&quot;:&quot;domain&quot;,&quot;investigation\_recommendation&quot;:&quot;Synthetic example only: investigate related activity and corroborate evidence\.&quot;,&quot;malicious&quot;:0,&quot;reputation\_status&quot;:&quot;synthetic\_suspicious&quot;,&quot;risk\_classification&quot;:&quot;elevated&quot;,&quot;source&quot;:&quot;Synthetic offline fixture&quot;,&quot;suspicious&quot;:2,&quot;validation\_reason&quot;:&quot;Valid domain syntax\.&quot;,&quot;validation\_status&quot;:&quot;valid&quot;\}
- No lookup was performed by the correlation engine\.

### Missing Evidence
- Authentication result and business context require analyst verification\.
- A baseline for this account and process lineage is not available\.
- Process lineage is not confirmed; no matching PID or process GUID relationship was established\.
- IOC observation time and independent confirmation are not available from the supplied result\.
- IOC observation time and independent DNS/domain context are not available from the supplied result\.

### Recommendations
- Review logon type, source context, account owner, and adjacent endpoint activity\.
- Confirm the logon was expected and inspect the process image, parent, command line, and change/deployment context\.
- Verify indicator provenance and compare destination, process, time, and approved network activity\.
- Validate IOC provenance and investigate resolver, process, destination, and related host activity\.

### MITRE ATT&CK Mappings
- T1059\.001 — PowerShell [UNVERIFIED — syntax only; not validated against a pinned ATT&CK reference.]
  - Rationale: The referenced Sysmon Event ID 1 records a PowerShell process invocation; this does not establish malicious intent\.
  - Evidence reference: related event 5; provenance matched; source references: source\_record:\[&quot;sysmon&quot;,&quot;soc\-lab\-01&quot;,&quot;microsoft\-windows\-sysmon/operational&quot;,&quot;7101&quot;\]

### Provenance and Evidence Limitations
- Related event 0: provenance matched; source references: source\_record:\[&quot;windows security&quot;,&quot;soc\-lab\-01&quot;,&quot;security&quot;,&quot;7001&quot;\]; source identity: \[&quot;windows security&quot;,&quot;soc\-lab\-01&quot;,&quot;security&quot;,&quot;7001&quot;\]; associated original record: present (not expanded); candidate record count: 1
- Related event 1: provenance matched; source references: source\_record:\[&quot;windows security&quot;,&quot;soc\-lab\-01&quot;,&quot;security&quot;,&quot;7002&quot;\]; source identity: \[&quot;windows security&quot;,&quot;soc\-lab\-01&quot;,&quot;security&quot;,&quot;7002&quot;\]; associated original record: present (not expanded); candidate record count: 1
- Related event 2: provenance matched; source references: source\_record:\[&quot;windows security&quot;,&quot;soc\-lab\-01&quot;,&quot;security&quot;,&quot;7003&quot;\]; source identity: \[&quot;windows security&quot;,&quot;soc\-lab\-01&quot;,&quot;security&quot;,&quot;7003&quot;\]; associated original record: present (not expanded); candidate record count: 1
- Related event 3: provenance matched; source references: source\_record:\[&quot;windows security&quot;,&quot;soc\-lab\-01&quot;,&quot;security&quot;,&quot;7004&quot;\]; source identity: \[&quot;windows security&quot;,&quot;soc\-lab\-01&quot;,&quot;security&quot;,&quot;7004&quot;\]; associated original record: present (not expanded); candidate record count: 1
- Related event 4: provenance matched; source references: source\_record:\[&quot;sysmon&quot;,&quot;soc\-lab\-01&quot;,&quot;microsoft\-windows\-sysmon/operational&quot;,&quot;7100&quot;\]; source identity: \[&quot;sysmon&quot;,&quot;soc\-lab\-01&quot;,&quot;microsoft\-windows\-sysmon/operational&quot;,&quot;7100&quot;\]; associated original record: present (not expanded); candidate record count: 1
- Related event 5: provenance matched; source references: source\_record:\[&quot;sysmon&quot;,&quot;soc\-lab\-01&quot;,&quot;microsoft\-windows\-sysmon/operational&quot;,&quot;7101&quot;\]; source identity: \[&quot;sysmon&quot;,&quot;soc\-lab\-01&quot;,&quot;microsoft\-windows\-sysmon/operational&quot;,&quot;7101&quot;\]; associated original record: present (not expanded); candidate record count: 1
- Related event 6: provenance matched; source references: source\_record:\[&quot;sysmon&quot;,&quot;soc\-lab\-01&quot;,&quot;microsoft\-windows\-sysmon/operational&quot;,&quot;7102&quot;\]; source identity: \[&quot;sysmon&quot;,&quot;soc\-lab\-01&quot;,&quot;microsoft\-windows\-sysmon/operational&quot;,&quot;7102&quot;\]; associated original record: present (not expanded); candidate record count: 1
- Related event 7: provenance matched; source references: source\_record:\[&quot;sysmon&quot;,&quot;soc\-lab\-01&quot;,&quot;microsoft\-windows\-sysmon/operational&quot;,&quot;7103&quot;\]; source identity: \[&quot;sysmon&quot;,&quot;soc\-lab\-01&quot;,&quot;microsoft\-windows\-sysmon/operational&quot;,&quot;7103&quot;\]; associated original record: present (not expanded); candidate record count: 1
- Limitation: No verified payload analysis was performed; the command line is inert synthetic text\.
- Limitation: Process lineage is not independently verified by a PID or ProcessGuid analysis module\.
- Limitation: No independently verified threat\-intelligence reputation is available; all IOC results are synthetic\.
- Limitation: No live endpoint investigation, Wazuh alert, or Wazuh rule\-engine validation occurred\.
- Limitation: No confirmed business impact or asset\-criticality information is available\.
- Limitation: Network and DNS process associations are analyst hypotheses based on matching event fields, not engine\-established links\.
Raw source records are not expanded in Markdown. JSON may contain explicit serialization markers for circular, unsupported, inaccessible, depth-limited, or non-finite values; review those markers before treating the serialized evidence as complete. Review JSON for sensitive data before sharing.
