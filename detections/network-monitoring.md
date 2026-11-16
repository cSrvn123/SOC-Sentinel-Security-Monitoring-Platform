# Network monitoring detections

**Status: Planned.** This file is a planning note for future network detection rules; it is not a deployed rule or a completed validation.

## Current implementation boundary

The local analyzer and correlation engine can process supplied Sysmon Event ID 3 network-connection and Event ID 22 DNS-query records, including separate matches to caller-supplied IOC results. Those associations do not prove that a DNS answer led to a particular connection or that an indicator is malicious. No live Wazuh network rule is validated here.

## Planned work

Specify the event source and fields, matching conditions, time/context requirements, expected alert, and evidence needed for analyst review. Include positive, negative and false-positive-context cases. Keep DNS-query and network-connection evidence distinct unless an explicit, tested relationship supports joining them.
