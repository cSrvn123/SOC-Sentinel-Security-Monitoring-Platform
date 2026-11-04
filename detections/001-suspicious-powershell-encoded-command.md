# Detection 001 — Suspicious PowerShell Encoded Command Execution

Status: Draft, not deployed to the running Wazuh Manager.

## Detection objective

Raise a high-priority alert when Windows PowerShell or PowerShell 7 starts with the `-EncodedCommand` or `-enc` switch. Encoded commands can conceal script intent and require analyst investigation; encoding alone does not prove malicious activity.

## Required telemetry

- Sysmon Event ID 1 (Process Create) from the Windows endpoint.
- Wazuh agent collection of `Microsoft-Windows-Sysmon/Operational`.
- Decoded fields `win.system.eventID`, `win.eventdata.image`, and `win.eventdata.commandLine`.
- The built-in Wazuh group `sysmon_event1`.

## Detection logic

Rule ID `100100`, level `10`, matches the `sysmon_event1` group, an image ending in `powershell.exe` or `pwsh.exe` (case-insensitive), and a command line containing a switch bounded as `-EncodedCommand` or `-enc` (case-insensitive). Both process-image and command-line conditions must match. The rule uses Wazuh PCRE2 field matching supported by the installed Wazuh 4.14.1 ruleset.

## MITRE ATT&CK mapping

- Tactic: Execution
- Technique: [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)

## Expected alert

- Rule ID: `100100`
- Level: `10`
- Description: `Suspicious PowerShell encoded command execution detected; encoded execution requires investigation.`
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

The XML is intended for Wazuh 4.14.1 syntax and is checked against the installed base rule and PCRE2 field-rule examples. Initial synthetic checks validate the XML and match logic in memory. They do not load this file into the running Manager or substitute for `wazuh-logtest` against an isolated copy of the custom rules. No real encoded command or payload is executed.
