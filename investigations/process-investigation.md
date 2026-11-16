# Process Investigation Worksheet

**Status: Template**

**Use:** Manually complete this worksheet from authorized process and event evidence. It is not an automated SOC Sentinel output or a completed investigation.

## Purpose and use

Use this worksheet to examine a process-creation event and its surrounding host context. Record what the source event actually contains, then treat process lineage, intent, and network ownership as questions to verify. A suspicious path, command-line option, hash result, or correlation alone does not prove malicious activity.

Record original timestamps exactly as shown, including timezone or UTC offset. If you normalize a time for comparison, preserve the original value as well. Mark missing fields `Not available`; do not fill them from assumptions.

## Case scope

- Investigation / alert ID:
- Analyst and date opened:
- Investigation question:
- Host / computer:
- Account / user context:
- Time window, with timezone:
- Alert or record source:
- Authorized data source and collection reference:

## Process evidence fields

Complete from an identified source record. These identifiers and properties may be present only in raw event data; do not assume SOC Sentinel normalized or verified them.

| Source-record reference | Event ID / source | Original timestamp and timezone | Process name | Image path | PID | ProcessGuid, if present | User/account | Command line / arguments |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | |

For each related observation below, cite the source record that contains it. For signature or hash verification, cite the independent verification source and record its reported result; do not present it as SOC Sentinel verification.

| Observation | Value / result | Source-record reference or independent verification source | Time / limitations |
|---|---|---|---|
| Parent image | | | |
| Parent command line, if present | | | |
| ParentProcessId, if present | | | |
| ParentProcessGuid, if present | | | |
| Hash algorithm and value, if available | | | |
| Signature status, if independently checked | | | |
| Related network event and its process fields | | | |
| Missing or ambiguous fields | | | |

For hashes, preserve the algorithm and exact value from the source; record any reputation result separately with provider, time, and status. Do not execute a command line or payload as part of this worksheet.

## Ordered investigation workflow

1. **Define scope.** Record the host, account, time window, alert/source, and the question to answer. Keep the event's original timestamp and timezone.
2. **Identify the process-creation record.** Capture its event ID, source-record reference, image, path, PID, ProcessGuid, user, and command line exactly as available. Mark absent fields rather than inferring them.
3. **Review executable and command context.** Compare the path, arguments, account, and time with approved software, change/deployment records, and expected host use. Treat path heuristics and encoded-command text as prompts, not proof of execution or intent.
4. **Assess parent fields carefully.** Record `ParentImage`, `ParentProcessId`, and `ParentProcessGuid` as fields observed in the child event. If examining a separate parent event, cite that record and compare host, time, PID, and GUID. SOC Sentinel does not independently validate PID or ProcessGuid lineage; describe an association as a hypothesis unless verified through independent evidence.
5. **Review hashes and signatures.** Use an authorized independent source if verification is needed. Record the source, observation time, exact result, and limitations. A hash or signature result is not by itself a conclusion about execution or intent.
6. **Review related network evidence separately.** Cite each network event and its process fields. SOC Sentinel does not verify process-to-network ownership; treat the relationship as a hypothesis unless independently corroborated.
7. **Check benign explanations and gaps.** Consider approved software deployment, system administration, scheduled tasks, legitimate scripts, and expected support activity. Identify evidence needed to distinguish them.
8. **Document a bounded conclusion.** Cite supporting and contrary evidence, retain unresolved hypotheses, and state what cannot be concluded.

## Observed facts

Record only facts directly present in identified process, parent, or corroborating records. Do not describe a matching parent field or nearby network event as proven lineage or ownership.

- Fact:
  - Source-record reference:
  - Exact field/value or observation:
- Fact:
  - Source-record reference:
  - Exact field/value or observation:

## Analyst hypotheses

| Hypothesis | Evidence supporting it (references) | Evidence against or alternative explanation | Verification needed | Status |
|---|---|---|---|---|
| | | | | Unverified |

## Missing evidence and limitations

- Missing event fields or related records:
- PID / ProcessGuid linkage not independently verified:
- Hash or signature verification source unavailable or incomplete:
- Process-to-network ownership not independently established:
- Timestamp, timezone, provenance, or source-reference limitations:
- Other evidence needed:

## Benign explanations to consider

- [ ] Approved software deployment or update.
- [ ] System administration or troubleshooting.
- [ ] Scheduled task or legitimate script.
- [ ] Expected parent process or user workflow for this host.
- [ ] Other explanation and evidence to check:

## Analyst conclusion and supporting evidence

- Conclusion / disposition:
- Supporting facts and source references:
- Contrary evidence and unresolved hypotheses:
- Confidence and its basis (separate from any correlation score):
- Severity, if assigned, and its independent rationale:
- Recommended follow-up:
- Reviewer / review date, if applicable:

Do not declare a process malicious from one heuristic, command-line string, hash/reputation result, parent field, or correlation. State what each cited source establishes and what remains unverified.

## Project limitations

The Windows Event Analyzer processes supplied JSON; it does not collect live endpoint events. It normalizes selected process fields, but hashes, ProcessGuid, and ParentProcessGuid may remain only in preserved raw evidence. The project does not independently verify process lineage, signatures, hashes, or process-to-network ownership. This worksheet is manual and does not imply live Wazuh integration or live SOC validation.

See the [Stage 7 case study](007-suspicious-powershell-case-study.md) and [architecture guide](../docs/ARCHITECTURE.md) for examples of these evidence boundaries.
