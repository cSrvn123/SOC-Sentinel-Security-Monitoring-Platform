# Sysmon configuration

`sysmonconfig.xml` is a minimal illustrative sample using XML schema version 4.90. It selects SHA-256 hashing and lists ProcessCreate (Event ID 1), NetworkConnect (Event ID 3), and DnsQuery (Event ID 22).

Each event filter uses `onmatch="exclude"` without child conditions. Under Sysmon's documented filter semantics, an empty exclude filter excludes no events of that type; if applied, this sample includes all events of the three listed types. This broad scope can produce high event volume and sensitive process, network, and DNS telemetry. Review and tune it for an authorized lab before use.

The file is an **unvalidated sample**. Its presence does not establish that it was installed, that telemetry was collected, or that events were delivered to SOC Sentinel or Wazuh. Check the schema against the installed Sysmon version and validate the configuration before any deployment. See Microsoft's [Sysmon configuration documentation](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files) and [enablement guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon).
