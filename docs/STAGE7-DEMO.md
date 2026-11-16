# Stage 7 — Synthetic SOC Investigation

This visual walkthrough follows the [Stage 7 case study](../investigations/007-suspicious-powershell-case-study.md) from initial scope through the analyst's final assessment.

> **Scope:** Synthetic training data only. This is not a live Wazuh alert or endpoint investigation. No live Wazuh alert or rule-engine validation was performed, no command or payload was executed, and no external IOC lookup was made. The ATT&CK mapping remains `UNVERIFIED`. Process, network, and DNS associations are hypotheses where documented, not confirmed links.

## Alert and scope

![Executive summary and exercise boundaries](../screenshots/stage7-screenshots-edited/stage7-section-01.png)

*Executive summary and exercise boundaries.*

![Synthetic input scope, initial triage, and host/account context](../screenshots/stage7-screenshots-edited/stage7-section-02.png)

*Synthetic input scope, initial triage, and host/account context.*

## Process and network investigation

![PowerShell process fields preserved in the synthetic Event ID 1 evidence](../screenshots/stage7-screenshots-edited/stage7-section-03.png)

*PowerShell process fields preserved in the synthetic Event ID 1 evidence.*

![Parent context and inert command-line assessment](../screenshots/stage7-screenshots-edited/stage7-section-04.png)

*Parent context and inert command-line assessment.*

![Network and DNS observations, with association limits](../screenshots/stage7-screenshots-edited/stage7-section-05.png)

*Network and DNS observations, with association limits.*

![Offline synthetic IOC results and the beginning of the event timeline](../screenshots/stage7-screenshots-edited/stage7-section-06.png)

*Offline synthetic IOC results and the beginning of the event timeline.*

## Timeline and correlation

![Incident timeline; timestamps establish ordering, not causality](../screenshots/stage7-screenshots-edited/stage7-section-07.png)

*Incident timeline; timestamps establish ordering, not causality.*

![Four separate engine correlation cases and test-only report composition](../screenshots/stage7-screenshots-edited/stage7-section-08.png)

*Four separate engine correlation cases and test-only report composition.*

![Evidence provenance and benign explanations to consider](../screenshots/stage7-screenshots-edited/stage7-section-09.png)

*Evidence provenance and benign explanations to consider.*

## Assessment and next steps

![Separate analyst severity and conclusion; ATT&CK mapping remains UNVERIFIED](../screenshots/stage7-screenshots-edited/stage7-section-10.png)

*Separate analyst severity and conclusion; ATT&CK mapping remains `UNVERIFIED`.*

![Missing evidence and recommended investigation steps](../screenshots/stage7-screenshots-edited/stage7-section-11.png)

*Missing evidence and recommended investigation steps.*
