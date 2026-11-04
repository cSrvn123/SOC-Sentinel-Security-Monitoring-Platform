# SOC Sentinel Architecture

```mermaid
flowchart TD
    A[Windows 11 Endpoint] --> B[Windows Security Event Logs]
    A --> C[Sysmon Telemetry]
    B --> D[Wazuh Agent]
    C --> D
    D --> E[Wazuh Manager]
    E --> F[Wazuh Indexer]
    F --> G[Wazuh Dashboard]
    F --> H[Python IOC Enrichment]
    H --> I[Detection Correlation]
    I --> J[MITRE ATT&CK Mapping]
    J --> K[Investigation Records and Reports]
```

The Windows endpoint produces security telemetry. The Wazuh Agent forwards configured events to the Wazuh Manager for decoding and rule evaluation. Alerts and state data are stored in the Indexer and viewed in the Dashboard. Python enrichment and analyst correlation support investigation and reporting.
