# Authentication detections

**Status: Planned.** This file is a planning note, not an implemented rule or a completed validation.

## Current implementation boundary

SOC Sentinel can analyze supplied Windows Security Event ID 4624 and 4625 records. Its local correlation engine also supports a repeated-failure-followed-by-success case. That behavior is not a deployed Wazuh rule or a live alert.

## Planned work

Define the source fields, account/host/source matching, time window and threshold before specifying a rule. Add positive, negative and false-positive-context cases, including expected output and limitations. Any future ATT&CK mapping must be supported by the case evidence and remain clearly distinguished from rule validation.
