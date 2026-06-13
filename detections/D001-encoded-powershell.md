D001 - Encoded PowerShell Execution

MITRE ATT&CK: T1059.001 (PowerShell), T1027 (Obfuscated Files)

Summary

Detected obfuscated PowerShell execution using base64 encoding - a common malware dropper technique to evade static analysis and command-line logging.

Attack Simulation

Executed the following on the Windows target:

powershell -nop -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAA...

Flags used by attackers:
  -nop: bypass PowerShell profile restrictions

  -w hidden: hide window from user

  -enc: base64 encoded payload (obfuscation)

Detection (KQL)

event.code: 1 AND process.name: "powershell.exe" AND process.command_line: (-enc OR -EncodedCommand)

Evidence

Kibana Discover showing Sysmon Event ID 1 with full command line telemetry including base64 payload, process hash (SHA256: d3b4b97c...), parent process, and user context.

Why It Matters

Legitimate scripts rarely combine -nop, -w hidden, and -enc together. This combination is a high-confidence indicator of malicious activity.
