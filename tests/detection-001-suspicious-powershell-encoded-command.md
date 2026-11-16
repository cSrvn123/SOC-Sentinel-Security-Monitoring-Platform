# Test plan — Detection 001: Suspicious PowerShell Encoded Command Execution

Status: Synthetic, in-memory validation only. No test command is executed on Windows and no rule is deployed to Wazuh.

## Objective and prerequisites

Verify that rule `100100` matches synthetic Sysmon Event ID 1 records in group `sysmon_event1` when the authoritative Sysmon `Image` field identifies `powershell.exe` or `pwsh.exe` and the command-line launcher options contain the exact `-EncodedCommand` or `-enc` switch. The first command-line token need not agree with `Image`. The XML must parse and use the Wazuh field-rule structure. These tests do not load the rule into a running Manager.

All values below are synthetic. `SYNTHETIC-TEST-DATA` is a literal inert placeholder and is not encoded data. Event fields not relevant to a case are omitted. All examples use a placeholder account and parent process; they are not copied from an endpoint.

## Synthetic cases

| Case | Synthetic event fields | Expected result and reason |
|---|---|---|
| P1 Positive: full switch | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand SYNTHETIC-TEST-DATA` | Match `100100`, level 10. Exact full switch follows the executable. |
| P2 Positive: abbreviated switch | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `powershell.exe -enc SYNTHETIC-TEST-DATA` | Match `100100`, level 10. Exact abbreviation follows the executable. |
| P3 Positive: mixed-case switch | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Program Files\PowerShell\7\pwsh.exe`; commandLine `"C:\Program Files\PowerShell\7\pwsh.exe" -eNc SYNTHETIC-TEST-DATA` | Match `100100`, level 10. Matching is case-insensitive. |
| P4 Positive: Windows PowerShell with launcher option | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand SYNTHETIC-TEST-DATA` | Match `100100`, level 10. A supported launcher option may precede the switch. |
| P5 Positive: PowerShell 7 | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Program Files\PowerShell\7\pwsh.exe`; commandLine `"C:\Program Files\PowerShell\7\pwsh.exe" -EncodedCommand SYNTHETIC-TEST-DATA` | Match `100100`, level 10. PowerShell 7 executable and full switch match. |
| P6 Positive: alternate executable paths | `win.system.eventID=1`; group `sysmon_event1`; image `D:\LabTools\PowerShell\pwsh.exe`; commandLine `D:\LabTools\PowerShell\pwsh.exe -enc SYNTHETIC-TEST-DATA` | Match `100100`, level 10. Matching uses the executable basename, not a fixed install directory. |
| N1 Negative: normal PowerShell | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `powershell.exe -Command Get-Process` | No match. No encoded-command launcher switch. |
| N2 Negative: NoProfile only | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `powershell.exe -NoProfile -Command Get-Date` | No match. `-NoProfile` alone is not suspicious for this rule. |
| N3 Negative: cmd.exe contains PowerShell text | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\cmd.exe`; commandLine `cmd.exe /c echo powershell.exe -enc SYNTHETIC-TEST-DATA` | No match. The process image is not PowerShell. |
| N4 Negative: wrong Sysmon group/event | `win.system.eventID=3`; group `sysmon_event3`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `powershell.exe -enc SYNTHETIC-TEST-DATA` | No match. The required group is `sysmon_event1`. |
| N5 Negative: similar but invalid switch | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `powershell.exe -EncodedCommandExtra SYNTHETIC-TEST-DATA` | No match. The switch name does not end at the required argument boundary. |
| N6 Negative: switch text only inside unrelated argument | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `powershell.exe -Command "Write-Output '-enc SYNTHETIC-TEST-DATA'"` | No match. `-Command` starts the command argument; the text inside it is not a launcher option. |
| FP1 False-positive scenario: approved endpoint administration | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `powershell.exe -EncodedCommand SYNTHETIC-TEST-DATA`; parentImage `C:\Lab\EndpointAdmin\agent.exe`; user `SYNTHETIC\svc-admin` | Match `100100`; analyst validates change record, expected host, parent process, and service account. This is a review scenario, not a suppression test. |
| FP2 False-positive scenario: software deployment | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Program Files\PowerShell\7\pwsh.exe`; commandLine `pwsh.exe -enc SYNTHETIC-TEST-DATA`; parentImage `C:\Lab\SoftwareDeploy\runner.exe`; user `SYNTHETIC\deploy` | Match `100100`; analyst checks deployment job and package/change records. Do not broadly allowlist the executable. |
| FP3 False-positive scenario: authorized red team | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `powershell.exe -EncodedCommand SYNTHETIC-TEST-DATA`; parentImage `C:\Lab\RedTeam\runner.exe`; user `SYNTHETIC\tester` | Match `100100`; analyst verifies exercise scope and time window with the exercise owner. Preserve the alert for auditability. |

## Preceding launcher-option coverage

Each row is an independent synthetic Event ID 1 event with group `sysmon_event1` and image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. The command line starts with the stated first token and option sequence, followed by `-EncodedCommand SYNTHETIC-TEST-DATA`. Every case must match `100100` at level 10.

| Case | Launcher option sequence | Expected result and reason |
|---|---|---|
| L1 | `powershell.exe -NoProfile -EncodedCommand SYNTHETIC-TEST-DATA` | Match. `-NoProfile` takes no value. |
| L2 | `powershell.exe -NonInteractive -EncodedCommand SYNTHETIC-TEST-DATA` | Match. `-NonInteractive` takes no value. |
| L3 | `powershell.exe -NoLogo -EncodedCommand SYNTHETIC-TEST-DATA` | Match. `-NoLogo` takes no value. |
| L4 | `powershell.exe -Sta -EncodedCommand SYNTHETIC-TEST-DATA` | Match. `-Sta` takes no value. |
| L5 | `powershell.exe -Mta -EncodedCommand SYNTHETIC-TEST-DATA` | Match. `-Mta` takes no value. |
| L6 | `powershell.exe -ExecutionPolicy RemoteSigned -EncodedCommand SYNTHETIC-TEST-DATA` | Match. `RemoteSigned` is a synthetic option value. |
| L7 | `powershell.exe -InputFormat Text -EncodedCommand SYNTHETIC-TEST-DATA` | Match. `Text` is a synthetic option value. |
| L8 | `powershell.exe -OutputFormat Text -EncodedCommand SYNTHETIC-TEST-DATA` | Match. `Text` is a synthetic option value. |
| L9 | `powershell.exe -ConfigurationName SyntheticConfig -EncodedCommand SYNTHETIC-TEST-DATA` | Match. `SyntheticConfig` is a synthetic option value. |
| L10 | `powershell.exe -Version 5.1 -EncodedCommand SYNTHETIC-TEST-DATA` | Match. `5.1` is a synthetic option value. |
| L11 | `powershell.exe -WindowStyle Hidden -EncodedCommand SYNTHETIC-TEST-DATA` | Match. `Hidden` is a synthetic option value. |

## Quoting, casing, spacing, and ordering

Every row has Event ID 1, group `sysmon_event1`, and a PowerShell image. The command-line executable token is intentionally not used as the process identity check.

| Case | Synthetic event fields | Expected result and reason |
|---|---|---|
| V1 Quoted executable path | image `C:\Program Files\PowerShell\7\pwsh.exe`; commandLine `"C:\Program Files\PowerShell\7\pwsh.exe" -enc SYNTHETIC-TEST-DATA` | Match. Quoted path with spaces is one first token. |
| V2 Unquoted executable path | image `D:\Tools\pwsh.exe`; commandLine `D:\Tools\pwsh.exe -enc SYNTHETIC-TEST-DATA` | Match. Unquoted path without spaces is one first token. |
| V3 Mixed-case executable and switch | image `c:\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE`; commandLine `POWERSHELL.EXE -eNc SYNTHETIC-TEST-DATA` | Match. Image and switch matching are case-insensitive. |
| V4 Multiple spaces | image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `powershell.exe   -NoProfile  -enc   SYNTHETIC-TEST-DATA` | Match. Repeated spaces remain valid separators. |
| V5 Tabs | image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `powershell.exe\t-NoLogo\t-enc\tSYNTHETIC-TEST-DATA` | Match. In this row, each literal `\t` denotes one tab character in the in-memory test string. |
| V6 Different supported option ordering | image `C:\Program Files\PowerShell\7\pwsh.exe`; commandLine `pwsh.exe -ExecutionPolicy RemoteSigned -NoProfile -WindowStyle Hidden -enc SYNTHETIC-TEST-DATA` | Match. Repeated supported options can appear in different orders before the encoded switch. |

## Image and command-line mismatch cases

For this rule, Sysmon `Image` is authoritative for the executable that created the process. The command-line first token is caller-supplied text and may not agree. An encoded-command switch in the launcher-option position should therefore still match when `Image` identifies PowerShell; a non-PowerShell `Image` must not match even if the command line contains PowerShell text.

| Case | Synthetic event fields | Expected result and reason |
|---|---|---|
| M1 Image powershell.exe, command line starts pwsh.exe | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `pwsh.exe -enc SYNTHETIC-TEST-DATA` | Match `100100`. Sysmon `Image` identifies PowerShell; the first command-line token does not gate the rule. |
| M2 Image pwsh.exe, command line starts another executable | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Program Files\PowerShell\7\pwsh.exe`; commandLine `notepad.exe -EncodedCommand SYNTHETIC-TEST-DATA` | Match `100100`. Sysmon `Image` identifies PowerShell; `notepad.exe` is only the synthetic first command-line token. |
| M3 Non-PowerShell image, command line contains encoded switch | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\cmd.exe`; commandLine `powershell.exe -enc SYNTHETIC-TEST-DATA` | No match. The authoritative `Image` field fails the PowerShell identity condition. |

## Incomplete and malformed switches

| Case | Synthetic event fields | Expected result and reason |
|---|---|---|
| N7 Truncated switch | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `powershell.exe -en SYNTHETIC-TEST-DATA` | No match. `-en` is not one of the exact switches selected by this rule. |
| N8 Invalid switch suffix | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `powershell.exe -encX SYNTHETIC-TEST-DATA` | No match. The switch has no valid argument boundary. |
| N9 Unsupported preceding option | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `powershell.exe -UnknownOption -enc SYNTHETIC-TEST-DATA` | No match. The rule only allows the documented launcher options before the encoded switch. |
| I1 Full switch without value | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; commandLine `powershell.exe -EncodedCommand` | Match `100100` as an invocation attempt. Event ID 1 does not prove that a valid command executed. |
| I2 Abbreviated switch without value | `win.system.eventID=1`; group `sysmon_event1`; image `C:\Program Files\PowerShell\7\pwsh.exe`; commandLine `pwsh.exe -enc` | Match `100100` as an invocation attempt. Event ID 1 does not prove that a valid command executed. |

The false-positive cases are expected alerts whose surrounding context may establish authorized activity. `SYNTHETIC-TEST-DATA` is never decoded or executed.

## Validation procedure and results

1. Parse the XML with Python's `xml.etree.ElementTree`.
2. Use Python's `re` engine to approximate the XML expressions for safe in-memory checks; this does not compile or validate PCRE2. Evaluate event group, event ID, image, and command line for every case above. Convert the `\t` notation in V5 to literal tab characters. No command lines are launched.
3. Require the positive, launcher-option, and formatting cases; M1–M2; I1–I2; and FP1–FP3 to match. Require N1–N9 and M3 not to match. These checks approximate the expressions; they are not Wazuh rule-engine tests.

### Results

- XML parse: **PASS**. Python `xml.etree.ElementTree` parsed the rule; rule ID `100100`, level `10`, `sysmon_event1` parent group, and both field conditions were present.
- Positive baseline: **6/6 PASS** (`P1`–`P6`). All six matched the image, command-line, event ID, and group conditions.
- Preceding launcher options: **11/11 PASS** (`L1`–`L11`). All documented options matched with their listed synthetic values.
- Quoting/casing/spacing/ordering: **6/6 PASS** (`V1`–`V6`). Quoted and unquoted paths, mixed case, repeated spaces, tabs, and reordered supported options matched.
- Negative coverage: **9/9 PASS** (`N1`–`N9`). None matched all conditions.
- Invocation attempts without values: **2/2 PASS** (`I1`–`I2`). Both matched as invocation attempts; neither establishes that a valid command executed.
- Image/command-line mismatch: **3/3 PASS** (`M1`–`M3`). M1 and M2 matched based on the PowerShell `Image`; M3 did not match because `Image` identified `cmd.exe`.
- False-positive context scenarios: **3/3 PASS as expected alerts** (`FP1`–`FP3`). Analyst context is needed to identify authorized activity.
- Total synthetic cases: **40/40 expected outcomes** in the local in-memory check.
- Wazuh rule-engine validation: **not performed**. No `wazuh-logtest` command was run, and the rule was not loaded into a Manager.

Python's regex behavior is not Wazuh PCRE2 rule-engine behavior. Deployment readiness requires a genuine isolated Wazuh 4.14.1 `wazuh-logtest` run with the complete decoder/ruleset and the test event format. Keep this draft undeployed until that validation is completed and reviewed.
