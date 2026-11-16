# Network Investigation Worksheet

**Status: Template**

**Use:** Manually complete this worksheet from authorized network, DNS, and reputation evidence. It is not an automated SOC Sentinel output or a completed investigation.

## Purpose and use

Use this worksheet to review a network connection and any potentially related DNS or process evidence. Keep each source event distinct until the relationship is corroborated. A destination, DNS query, reputation result, or time proximity alone does not establish malicious activity or prove which process owned a connection.

Record timestamps exactly as shown in each source, including timezone or UTC offset. If you normalize times for comparison, retain the originals. Use separate references for the connection, DNS, and process records; mark unavailable fields rather than inferring them.

## Case scope

- Investigation / alert ID:
- Analyst and date opened:
- Investigation question:
- Host / computer:
- Account / user context, if available:
- Time window, with timezone:
- Alert or record source:
- Authorized data source and collection reference:

## Network connection fields

Complete one row per connection event. Preserve the source event and distinguish source fields from analyst-created associations.

| Source-record reference | Event ID / source | Original timestamp and timezone | Direction, if known | Local IP:port | Remote IP:port | Protocol | Outcome, if available | Process details and their evidence reference |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | |

## DNS evidence fields

Record DNS events separately. An observed query is not proof that the name resolved to a particular address or that a later connection used the answer.

| DNS source-record reference | Event ID / source | Original timestamp and timezone | Host | Query name | Resolver | Answer / record type, if available | Notes / missing fields |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

## Reputation context

| Indicator and type | Provider / source | Lookup or observation time | Result / status | Label (synthetic, offline, or external lookup) | Source reference and limitations |
|---|---|---|---|---|---|
| | | | | | |

Do not call an offline fixture external intelligence. If an external lookup is authorized, document the provider, time, and disclosure approval according to local policy. An external provider's output is a reported reputation result, not independent proof that an indicator or associated connection is malicious or benign.

## Ordered investigation workflow

1. **Define scope.** Record the host, time window, alert/source, and investigation question. Note timezone and authorized evidence sources.
2. **Validate each connection record.** Capture event ID, timestamp, direction if available, local and remote endpoints, protocol, outcome, and stable source reference. Keep raw values available where the analyzer does not normalize them.
3. **Review DNS separately.** Record the query, resolver, answer, timestamp, and source reference when present. Compare records by time and host, but do not assume an Event ID 22 answer was used by an Event ID 3 connection.
4. **Assess process context.** Record process name, image, PID, or other identifiers only with the event/source reference that contains them. SOC Sentinel does not independently verify process ownership of a network connection; label any association as a hypothesis until corroborated.
5. **Evaluate reputation provenance.** Record provider, result, lookup time, and whether the value is synthetic/offline or came from an external lookup. Confirm any external disclosure was authorized. Treat the provider output as reported reputation context, not a verdict about the indicator or connection.
6. **Check expected network use.** Review approved proxies, VPNs, CDNs, software updates, resolver behavior, and host role with an independent source or owner when available.
7. **Record limits and conclude carefully.** Cite evidence for and against each hypothesis, note missing data, and state the conclusion only as strongly as the evidence allows.

## Observed facts

Include only values present in identified source records or independently verified context. Keep analyst joins or interpretations out of this section.

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

- Missing connection, DNS, process, or resolver records:
- Direction, outcome, endpoint, or port fields unavailable:
- DNS answer or connection-to-query relationship not established:
- Process ownership not independently corroborated:
- Reputation source, lookup time, or verification status unavailable:
- Timestamp, timezone, provenance, or source-reference limitations:
- Other evidence needed:

## Benign explanations to consider

- [ ] Approved proxy, VPN, NAT, or security gateway.
- [ ] CDN, cloud-hosted service, or shared destination infrastructure.
- [ ] Approved software update, application, or business service.
- [ ] Expected DNS resolver, caching, or administrative activity.
- [ ] Other explanation and evidence to check:

## Analyst conclusion and supporting evidence

- Conclusion / disposition:
- Supporting facts and source references:
- Contrary evidence and unresolved hypotheses:
- Confidence and its basis (separate from any correlation score):
- Severity, if assigned, and its independent rationale:
- Recommended follow-up:
- Reviewer / review date, if applicable:

Do not conclude that a connection is malicious solely from its destination, a DNS query, an IOC match, or a reputation score. Explain whether a process or DNS association is observed, independently corroborated, or still hypothetical.

## Project limitations

The Windows Event Analyzer reads supplied JSON, not live network telemetry. For Sysmon Event ID 3, selected address and process fields are normalized while protocol and port values remain in raw evidence. For Event ID 22, the query name may be normalized while query results remain raw. SOC Sentinel does not prove that a DNS answer was used by a connection or verify process ownership. This worksheet is manual and does not imply live Wazuh integration or live SOC validation.

See the [Stage 7 case study](007-suspicious-powershell-case-study.md) and [architecture guide](../docs/ARCHITECTURE.md) for examples of these evidence boundaries.
