# Test plan — Detection 001: Suspicious PowerShell Encoded Command Execution

Status: Synthetic, in-memory validation only. No test command is executed on Windows and no rule is deployed to Wazuh.

## Objective and prerequisites

Verify that rule `100100` matches Sysmon Event ID 1 records in group `sysmon_event1` only when the image is `powershell.exe` or `pwsh.exe` and the command line contains `-EncodedCommand` or `-enc`. The rule XML must parse, use the installed Wazuh 4.14.1 field-rule structure, and remain outside the running Manager until separately approved.

## Synthetic cases

| Case | Synthetic event fields | Expected result |
|---|---|---|
| Positive: full switch | `eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; command line `powershell.exe -EncodedCommand SYNTHETIC-TEST-DATA` | Match rule `100100`, level 10 |
| Positive: abbreviated switch / PowerShell 7 | `eventID=1`; group `sysmon_event1`; image `C:\Program Files\PowerShell\7\pwsh.exe`; command line `pwsh.exe -enc SYNTHETIC-TEST-DATA` | Match rule `100100`, level 10 |
| Negative: normal PowerShell | `eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; command line `powershell.exe -Command Get-Process` | No match |
| Negative: NoProfile only | `eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; command line `powershell.exe -NoProfile -Command Get-Date` | No match |
| Negative: wrong image | `eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\cmd.exe`; command line `cmd.exe /c powershell.exe -enc SYNTHETIC-TEST-DATA` | No match |
| Negative: wrong event group | `eventID=3`; group `sysmon_event3`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; command line `powershell.exe -enc SYNTHETIC-TEST-DATA` | No match |

`SYNTHETIC-TEST-DATA` is a literal placeholder, not encoded content. No payload is created or run.

## Actual result and limitations

The local XML parser and in-memory matcher results are recorded in the handoff report. These checks do not prove Wazuh's full rule-engine behavior because the new rule is intentionally not loaded into the running Manager. A future isolated `wazuh-logtest` run should confirm exact engine matching before deployment.
