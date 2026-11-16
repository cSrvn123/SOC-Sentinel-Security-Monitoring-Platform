# Authentication Investigation Worksheet

**Status: Template**

**Use:** Manually complete this worksheet from authorized security-event records. It is not an automated SOC Sentinel output or a completed investigation.

## Purpose and use

Use this worksheet to review a reported sign-in or authentication pattern, such as repeated failures, a successful sign-in, or an unfamiliar source. Event IDs 4624 and 4625 describe successful and failed logon events respectively; neither event alone proves compromise, identifies who owns an account, or explains whether the activity was expected.

Record timestamps as shown in the source, including the timezone or UTC offset. If you calculate a normalized time for comparison, keep the original timestamp too. Use `Not available` when a field is missing; do not infer it from a nearby event.

## Case scope

- Investigation / alert ID:
- Analyst and date opened:
- Investigation question:
- Host / computer:
- Account under review:
- Time window, with timezone:
- Alert or record source:
- Authorized data source and collection reference:

## Evidence collection fields

Create one row for each relevant authentication record. Keep source references stable so another analyst can find the same record.

| Source-record reference | Event ID / source | Original timestamp and timezone | Outcome | Account / host | Logon type and documented meaning | Source IP / workstation | Logon process or package | Notes / unavailable fields |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | |

For logon type, record the value from the event and the reference used to interpret it. If the meaning cannot be confirmed from an approved event schema or source, mark it unknown rather than guessing.

## Ordered investigation workflow

1. **Define the question and scope.** Identify the alert, host, account, and time range. Note the source system and timezone so the search can be repeated.
2. **Validate the source records.** Record each event ID, original timestamp, outcome, host, account fields, and source-record reference. Distinguish 4624 success events from 4625 failure events; do not treat an event ID as a verdict.
3. **Review sign-in context.** Capture logon type, source IP, workstation, and logon process/package when present. Record which fields are absent or ambiguous. These details can help characterize the sign-in but do not establish account ownership or intent.
4. **Build the related-event sequence.** List relevant successes and failures in timestamp order. Compare host, account, source, and time window; identify records that do not match the investigated account or host instead of silently grouping them.
5. **Check expected activity.** Seek authorized confirmation of account owner, service or administrative purpose, host role, scheduled activity, and applicable change records. Record the source of each confirmation.
6. **Consider alternatives and gaps.** Note plausible user error, saved credentials, expected service activity, VPN/NAT address sharing, or other context. State what evidence would distinguish these explanations.
7. **Write a bounded conclusion.** Summarize only what the referenced records support. Identify what remains unverified and what additional authorized evidence is needed.

## Observed facts

Include only details directly present in identified records or independently verified sources. For each fact, cite the source-record reference.

- Fact:
  - Source reference:
  - Exact field/value or observation:
- Fact:
  - Source reference:
  - Exact field/value or observation:

## Analyst hypotheses

Record possible explanations separately from facts. A hypothesis remains unverified until corroborating evidence supports it.

| Hypothesis | Evidence supporting it (references) | Evidence against or alternative explanation | Verification needed | Status |
|---|---|---|---|---|
| | | | | Unverified |

## Missing evidence and limitations

- Missing fields or records:
- Account ownership / privilege context still to verify:
- Host role or business purpose still to verify:
- Timestamp, timezone, source-reference, or provenance limitations:
- Other data that would materially change the assessment:

## Benign explanations to consider

Check or add explanations only when relevant; record how each was assessed.

- [ ] User mistyped a password or used stale saved credentials.
- [ ] Expected service, scheduled task, or administrative activity.
- [ ] VPN, NAT, shared workstation, or other source-address context.
- [ ] Approved maintenance, deployment, or support activity.
- [ ] Other explanation and evidence to check:

## Analyst conclusion and supporting evidence

- Conclusion / disposition:
- Supporting facts and source references:
- Contrary evidence and unresolved hypotheses:
- Confidence and its basis (separate from any correlation score):
- Severity, if assigned, and its independent rationale:
- Recommended follow-up:
- Reviewer / review date, if applicable:

Do not label activity malicious solely because it includes a failed or successful logon, an unfamiliar source, or a correlation. Explain what the evidence establishes and what it does not.

## Project limitations

SOC Sentinel can normalize supported Security Event IDs 4624 and 4625 from supplied JSON and provide heuristic or correlation context. It does not read live Windows event channels, verify account ownership, establish business purpose, or make the analyst’s conclusion. This worksheet is completed manually; it does not imply live Wazuh integration or live SOC validation.

For implementation context, see the [architecture guide](../docs/ARCHITECTURE.md) and [Python package guide](../python/README.md).
