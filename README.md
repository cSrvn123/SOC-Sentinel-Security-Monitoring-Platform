# SOC Sentinel

**Security Monitoring, Threat Detection & Incident Investigation Platform**

SOC Sentinel is a practical Windows endpoint monitoring and SOC investigation lab built around Wazuh, Sysmon, Python-based IOC enrichment, and MITRE ATT&CK.

## Project goals

- Collect Windows security and Sysmon telemetry.
- Centralize endpoint events in Wazuh.
- Build and test detections for authentication, process, network, and file activity.
- Enrich IP addresses, domains, and SHA-256 hashes with threat intelligence.
- Map relevant detections to MITRE ATT&CK.
- Produce evidence-based investigation reports.

## Architecture

Windows 11 endpoint (Windows Security logs + Sysmon)
→ Wazuh Agent
→ Wazuh Manager
→ Wazuh Indexer and Dashboard
→ Python IOC enrichment
→ Detection correlation, MITRE mapping, investigation reports

See `architecture/architecture.md`.

## Technology stack

- Wazuh: SIEM, endpoint monitoring, rules, dashboards, and File Integrity Monitoring.
- Sysmon: detailed process, network, file, registry, and DNS telemetry.
- Python: IOC validation and enrichment.
- VirusTotal API: reputation lookups (API key stored outside source control).
- MITRE ATT&CK: tactic and technique mapping.
- Git and GitHub: version control and project documentation.

## Repository status

This repository is being built incrementally. A feature is marked complete only after its configuration, test evidence, and documentation have been verified.

| Phase | Status |
|---|---|
| Environment and SIEM audit | Existing Wazuh deployment verified; storage review remains separate |
| Windows endpoint and Sysmon | Pending |
| Authentication and process monitoring | Pending |
| Network investigation | Pending |
| IOC enrichment | Pending |
| Detection engineering | Pending |
| MITRE ATT&CK mapping | Pending |
| File Integrity Monitoring | Pending |
| Dashboard and reporting | Pending |
| Controlled testing | Pending |
| GitHub documentation and release | Pending |

## Safety and privacy

- Use only systems and networks you own or are authorized to test.
- Use controlled simulations; do not use real malware or destructive tests.
- Do not commit API keys, passwords, private logs, or personal information.
- Sanitize screenshots and event samples before publishing.
- Reputation scores are supporting context, not proof that an indicator is malicious.

## Project structure

- `architecture/` — system design
- `wazuh/` — Wazuh configuration and custom rules
- `sysmon/` — Sysmon configuration
- `python/` — IOC enrichment tools
- `detections/` — detection logic and rationale
- `investigations/` — investigation playbooks and case notes
- `tests/` — controlled test plans and results
- `reports/` — sanitized incident reports
- `screenshots/` — sanitized project evidence

## Setup

Detailed setup instructions will be added as each component is implemented and verified.
