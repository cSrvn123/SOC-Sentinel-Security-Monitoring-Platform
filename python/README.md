# Python IOC enrichment

SOC Sentinel's IOC enrichment module validates indicators locally and provides synthetic offline examples by default. Optional VirusTotal API v3 lookups are available only when an analyst explicitly authorizes disclosure of an indicator to VirusTotal.

## Capabilities

- Detects and validates IPv4, IPv6, domain names, HTTP(S) URLs, MD5, SHA-1, and SHA-256 values.
- Separates indicator validation, classification, reputation providers, orchestration, and result formatting.
- Uses only the Python standard library; no package installation is required.
- Offline fixtures demonstrate benign, suspicious, and unknown outcomes. They are synthetic examples, not real threat intelligence.
- VirusTotal mode performs read-only `GET` lookups for existing indicator reports. It has no file upload or sample submission function.

## Privacy before live lookup

VirusTotal documents that indicators queried through its API may be scanned and added to its dataset, where they can be accessible to the community. Do not query confidential, internal-only, personal, or otherwise sensitive indicators. The CLI requires both `--live` and `--allow-indicator-sharing` so disclosure is an explicit action. Tests do not make live requests.

## Setup

Requirements: Python 3.10 or later. From the project root, enter the `python` folder. No dependencies need to be installed.

```powershell
cd D:\Portfolio\Cybersecurity\SOC-Sentinel\python
```

## Offline execution

Offline mode is the default and does not access the network:

```powershell
python -m ioc_enrichment.cli 198.51.100.10
python -m ioc_enrichment.cli suspicious.example --json
python -m ioc_enrichment.cli 192.0.2.44
```

These examples use documentation IP ranges and the reserved `.example` domain. Their labels are synthetic and are not actual reputation findings. Indicators without a fixture return a synthetic unknown result.

## Optional VirusTotal configuration

Store the API key in the environment variable `VIRUSTOTAL_API_KEY`, never in source files, command arguments, screenshots, or Git. In PowerShell, set it for the current session without echoing it:

```powershell
$secureKey = Read-Host 'Enter VirusTotal API key' -AsSecureString
$env:VIRUSTOTAL_API_KEY = (New-Object System.Net.NetworkCredential('', $secureKey)).Password
Remove-Variable secureKey
```

When finished, remove the variable from the current PowerShell session:

```powershell
Remove-Item Env:VIRUSTOTAL_API_KEY
```

Live mode requires explicit acknowledgment that the indicator will be disclosed to VirusTotal:

```powershell
python -m ioc_enrichment.cli 8.8.8.8 --live --allow-indicator-sharing
```

Live lookup requests metadata only. It does not upload files or samples. VirusTotal account access, API limits, and service terms apply; the tool makes no claim that API access is free or that any indicator is safe. HTTP errors, 404 responses, rate limits, malformed responses, and network timeouts are handled without printing request credentials. A zero detection count is classified as unknown; harmless votes are not proof of safety.

## Tests

From the `python` folder, run the standard-library unit tests:

```powershell
python -m unittest discover -s tests -v
```

Tests use synthetic values and mocked HTTP responses. They do not contact VirusTotal or execute indicator content.

## Analyst result fields

Each result contains the indicator, detected type, validation status, reputation status, risk classification, source, investigation recommendation, and validation reason. Optional analysis counts and safe error descriptions are included when available. Offline output explicitly labels itself synthetic.

## Package layout

- `ioc_enrichment/classification.py` — syntax-based type identification.
- `ioc_enrichment/validation.py` — format validation and normalization.
- `ioc_enrichment/reputation.py` — synthetic provider and VirusTotal GET-only provider.
- `ioc_enrichment/enrichment.py` — validation and provider orchestration.
- `ioc_enrichment/formatting.py` — analyst-friendly text and JSON output.
- `ioc_enrichment/cli.py` — command-line interface.
- `tests/` — unit tests with no network calls.

## Windows Security Event Analyzer

The separate `windows_event_analyzer` package reads local JSON records and produces a common event structure plus cautious analyst observations. It supports Windows Security events 4624 and 4625, and Sysmon events 1, 3, and 22. It performs no network access and does not change Windows settings or read Windows event logs directly.

### Input and execution

Input may be one JSON event object or an array of event objects. The parser accepts direct fields, common Wazuh `win.system` / `win.eventdata` fields, and Event Viewer-style `Event.System` / `Event.EventData` layouts. Unsupported records are counted as input issues; missing optional event fields remain `null`.

From the `python` folder, analyze the included synthetic sample:

```powershell
python -m windows_event_analyzer.cli --input windows_event_analyzer/examples/synthetic_events.json
python -m windows_event_analyzer.cli --input windows_event_analyzer/examples/synthetic_events.json --format json
```

Configure the failed-logon threshold and time window (for example, 5 failures within 120 seconds):

```powershell
python -m windows_event_analyzer.cli --input windows_event_analyzer/examples/synthetic_events.json --failed-logon-threshold 5 --failed-logon-window-seconds 120
```

The analyzer can read JSON from standard input when the calling shell passes UTF-8 input reliably; using `--input` is the recommended Windows PowerShell workflow.

### Observations and interpretation

- Repeated failed logons use a default threshold of 3 Event ID 4625 records within 300 seconds. Correlation keys include the computer and whichever of account or source IP is available; events with neither are not grouped.
- Only timestamps with an explicit UTC offset are eligible. Timestamps are converted to UTC, so mixed offsets and out-of-order input are handled consistently. Missing, invalid, or timezone-naive timestamps are reported and excluded from time-window correlation.
- Process observations flag execution from selected commonly writable paths and selected Office-to-interpreter parent-child pairs.
- Network observations identify a globally routable destination address in Sysmon Event ID 3.
- DNS observations flag heuristic features such as punycode labels, many subdomain labels, or an unusually long label.

Each observation includes the heuristic reason and, for correlated failures, the matched count, threshold, and UTC time span. These are investigation prompts, not confirmed attacks or proof of compromise. The process and DNS heuristics are intentionally simple and can produce false positives. A globally routable destination is network context only; public routability does not assign a malicious reputation. Review event context and corroborating telemetry before drawing conclusions. The included event JSON is synthetic; it is not a real endpoint log. It includes an incomplete event and an unsupported synthetic event to demonstrate safe handling. The report preserves the original input records alongside normalized records.

### Tests

Run all Python tests, including IOC Enrichment and this analyzer, from the `python` folder:

```powershell
python -m unittest discover -s tests -v
```

Tests use synthetic records only and do not query external services or access Windows event logs.

## Alert Correlation Engine

The separate `alert_correlation` package consumes `AnalysisReport` / `NormalizedEvent` objects from `windows_event_analyzer` and optional existing `EnrichmentResult` objects from `ioc_enrichment`. It does not invoke IOC enrichment, VirusTotal, or any other network service.

### Correlation patterns

- Repeated Event ID 4625 failures followed by Event ID 4624 success for the same computer and account, with matching source IP when both sides provide one.
- Event ID 4624 followed by an Event ID 1 process that already has a Windows Event Analyzer unusual-context observation; matching parent process events are included when available.
- Sysmon Event ID 3 destination IP matching a supplied, valid IOC result.
- Sysmon Event ID 22 DNS query matching a supplied, valid domain or URL IOC result.

Correlation requires timezone-aware timestamps and a known computer. Logon/process patterns also require account identity. Duplicate normalized events are deduplicated for counting while all normalized source references are retained. Cases preserve the original source record batch when given an `AnalysisReport`.

```python
from datetime import timedelta
from alert_correlation import CorrelationConfig, correlate
from windows_event_analyzer.analyzer import analyze_records

report = analyze_records(synthetic_records)
config = CorrelationConfig(
    failed_logon_threshold=3,
    failed_to_success_window=timedelta(minutes=10),
    logon_to_process_window=timedelta(minutes=10),
)
cases = correlate(report, ioc_results=existing_ioc_results, config=config)
```

This is an illustrative API sequence, not a standalone script: `synthetic_records` and `existing_ioc_results` must be provided by the caller before running it. For a complete example that loads the included synthetic fixture, see the root README's [Correlation and incident reporting APIs section](../README.md#correlation-and-incident-reporting-apis).

Use `alert_correlation.formatting.format_json(cases)` or `format_text(cases)` for reports. Each case includes evidence, missing evidence, recommendations, related event references, involved identities, and confidence with an explanation. Confidence describes the strength of the correlation only. A match or reputation value is not an automatic malicious verdict or proof of compromise. IOC case evidence reflects only the supplied result and its source; IOC results do not carry observation timestamps, so the engine cannot prove that a lookup preceded the endpoint event.

Run the complete synthetic unit-test suite from the `python` folder:

```powershell
python -m unittest discover -s tests -v
```

## Incident reporting formatters

Incident Reporting supports JSON exports and analyst-oriented Markdown reports:

```python
from incident_reporting import format_json, format_markdown

json_export = format_json(incident_collection)
markdown_report = format_markdown(incident_collection)
```

Pass an `IncidentReport` for a single incident or an `IncidentReportCollection` for a batch. JSON preserves the complete modeled incident and collection data, including accessible raw source records. It uses explicit serialization markers for circular references, excessive nesting (maximum depth 128), unsupported values, non-finite numbers, and inaccessible attributes. A marker means the represented value could not be serialized normally; it must not be treated as complete evidence.

**Review JSON exports before sharing.** Original event records and evidence may contain credentials, personal information, host details, command lines, or other sensitive log data. JSON formatting does not redact or alter that evidence. Markdown provides concise evidence and provenance summaries and does not expand raw source records by default. Both formatters render event-derived text as data; they do not execute it or interpret it as markup.

ATT&CK mappings marked `UNVERIFIED` are shown as unverified. Identifier syntax checking does not confirm that an ID, technique name, or tactic is officially present in ATT&CK.
