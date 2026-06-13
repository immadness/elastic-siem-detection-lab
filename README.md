# elastic-siem-detection-lab
Home SOC lab simulating attacker TTPs and building detection engineering skills using Elastic SIEM with Sysmon endpoint telemetry.
Architecture

Attacker: Kali Linux (UTM VM)
Target: Windows laptop (physical endpoint)
SIEM: Elastic Stack 8.13 (Docker) - Elasticsearch + Kibana
Log pipeline: Sysmon + Winlogbeat to Elasticsearch

Tools
Elastic Stack 8.13, Sysmon (SwiftOnSecurity config), Winlogbeat, Kali Linux, Docker
Detections
ID: D001
Detection: Encoded Powershell Execution
MITRE: T1059.001,T1027
Event ID: Sysmon 1
