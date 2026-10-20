# Atomic Red Team – Technique Analysis

Foundational, single-technique detection studies carried out in a self-built home lab. Each scenario simulates one MITRE ATT&CK technique with [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) on a Windows VM, then investigates the resulting telemetry in Splunk — reconstructing what happened from logs, identifying indicators of compromise, and surfacing detection coverage gaps.

The emphasis is on the **analyst workflow**: forming a hypothesis before execution, tracing process lineage from raw event fields, distinguishing tooling noise from real technique behavior, and validating findings across multiple log sources rather than trusting any single one.

## Lab Environment

| Component | Detail |
|---|---|
| Victim host | Windows VM |
| Telemetry | Sysmon (process, file, registry events), Windows Security Event Log (4688 with command-line auditing), PowerShell Script Block Logging (4104) and Module Logging (4103) |
| SIEM | Splunk |
| Attack simulation | Invoke-AtomicRedTeam (`Invoke-AtomicTest`) |

## Scenarios

| # | Tactic | Technique | Outcome |
|---|---|---|---|
| 1 | Execution | [T1059.003 – Windows Command Shell](./execution-command-shell-script-write-and-execute/) | Technique executed; full process chain reconstructed |
| 2 | Persistence | [T1547.001 – Registry Run Keys / Startup Folder](./persistence-startup-folder-registry-modification/) | Technique executed; Sysmon coverage gap identified and root-caused |
| 3 | Privilege Escalation | [T1548.002 – Bypass User Account Control](./privilege-escalation-uac-bypass-silentcleanup/) | Technique attempted but failed; failure root-caused via native OS diagnostics |

## Approach

Each scenario folder contains:
- **`README.md`** — the full write-up: objective, technique overview, methodology, investigation findings, IOCs, lessons learned, and recommendations.
- **`queries.spl`** — the Splunk searches used during the investigation.

These studies were produced as deliberate skill-building exercises. Conclusions were reasoned from the evidence rather than copied from technique documentation, including cases where a technique behaved differently than its public write-up suggested.
