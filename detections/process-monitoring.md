# Process monitoring detections

**Status: Planned.** This file covers broader future process-detection work; it is not an implemented rule or a completed validation.

## Current implementation boundary

The analyzer emits selected heuristic observations from supplied process events. Detection 001 is a separate draft PowerShell rule and remains undeployed; Wazuh rule-engine validation is `NOT_RUN`. Neither a process observation nor a draft rule proves malicious execution or verified parent/child lineage.

## Planned work

Define the process event source, fields and matching logic, then add synthetic positive, negative and false-positive-context cases. Treat command lines as evidence, not proof of execution or intent. Describe parent-process and related-network fields as contextual evidence unless an independently supported relationship is available. Record limitations and any evidence-backed ATT&CK mapping separately.
