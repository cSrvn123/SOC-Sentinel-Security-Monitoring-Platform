# Detection 001 — Suspicious PowerShell Encoded Command Execution

Status: Draft, not deployed to the running Wazuh Manager.

## Detection objective

Raise a high-priority alert when Windows PowerShell (`powershell.exe`) or PowerShell 7 (`pwsh.exe`) is launched with the `-EncodedCommand` or `-enc` command-line switch. Encoded commands can conceal script intent and require analyst investigation; encoding alone does not prove malicious activity.

## Required telemetry

- Sysmon Event ID 1 (Process Create) from the Windows endpoint.
- Wazuh agent collection of `Microsoft-Windows-Sysmon/Operational`.
- Decoded fields `win.system.eventID`, `win.eventdata.image`, `win.eventdata.commandLine`, and the `sysmon_event1` group assigned by the built-in Sysmon decoder.
- The built-in Wazuh group `sysmon_event1`.

## Detection logic

Rule ID `100100`, level `10`, requires the `sysmon_event1` group, an image ending in `powershell.exe` or `pwsh.exe`, and a command line whose first token is followed by supported launcher options and an exact `-EncodedCommand` or `-enc` option. The Sysmon `Image` field is authoritative for process identity; the command-line first token is not required to agree with it. Matching is case-insensitive. The command-line expression requires a token boundary after the switch, so names such as `-EncodedCommandExtra` do not match. It only looks for the switch in the launcher-option sequence before command/script arguments; text such as `-enc` inside a `-Command` argument does not satisfy the rule.

Supported options before the encoded-command switch are `-NoProfile`, `-NonInteractive`, `-NoLogo`, `-Sta`, `-Mta`, `-ExecutionPolicy`, `-InputFormat`, `-OutputFormat`, `-ConfigurationName`, `-Version`, and `-WindowStyle`. Options that take a value are modeled with one following argument. Other launcher options or unusual command-line quoting may not match and should be checked against actual decoded Sysmon events before deployment. The command-line first token can be quoted or unquoted; its text is not used as the process-identity check.

## MITRE ATT&CK mapping

- Tactic: Execution
- Technique: [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)

## Expected alert

- Rule ID: `100100`
- Level: `10`
- Description: `Suspicious PowerShell encoded-command invocation attempt detected; investigation is required.`
- The alert should identify the Windows endpoint and Sysmon process-create event. Review decoded process and parent-process details in the authorized Wazuh interface; do not copy command-line arguments into shared reports.

## False positives

- Endpoint-management and software-deployment tools may use encoded command lines.
- Administrators may encode scripts to pass arguments safely or avoid quoting problems.
- Red-team exercises and approved automation can produce the same pattern.
- Validate the parent process, account, host role, change records, file hash, and related network/DNS activity before treating the alert as malicious.
- `-NoProfile` alone is not part of this rule because it is common in legitimate automation.

## Investigation steps

1. Confirm the event is Sysmon Event ID 1 and the image is `powershell.exe` or `pwsh.exe`.
2. Review the parent image, account, timestamp, host role, and file hash in the authorized console.
3. Determine whether the execution matches approved administration, deployment, or testing activity.
4. Correlate the process with nearby network-connection and DNS events and related endpoint alerts.
5. Preserve evidence and follow the SOC incident process if the activity is unexplained. This rule performs alerting only; it has no active response.

## Validation status and limitations

The XML is intended for Wazuh 4.14.1 syntax. A bare `-EncodedCommand` or `-enc` switch with no following value is treated as an invocation attempt; the process-create event does not prove that a valid command executed. XML parsing and synthetic in-memory regular-expression checks are documented in the companion test plan. They do not load this file into the Wazuh rule engine and do not substitute for `wazuh-logtest` in an isolated environment with the complete matching ruleset. No real encoded command or payload is executed. Deployment status remains **draft, not deployed**.
