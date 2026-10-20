# Persistence – Startup Folder Registry Modification

**MITRE ATT&CK:** [T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

## 1. Objective / Scope

Simulate and investigate a Windows persistence technique using Atomic Red Team, with the goal of practicing registry-based event analysis, correlating telemetry across a system reboot, and identifying detection coverage gaps in Sysmon configuration, using Splunk as the SIEM.

## 2. Technique Overview

| Field | Detail |
|---|---|
| Tactic | Persistence (TA0003) |
| Technique | T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| Atomic Test | Test #10: "Change Startup Folder - HKLM Modify User Shell Folders Common Startup Value" |
| Mechanism | Modifies `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, value `Common Startup`, redirecting the system-wide Startup folder to an attacker-controlled path. Requires a system reboot for the redirected Startup path to take effect. |

**Privilege note:** Targets HKLM (machine-wide, all users) rather than HKCU (per-user), requiring elevated privileges to write but affecting every user on the host — a higher-impact variant of the technique.

## 3. Environment

- **Victim host:** Windows VM (host1)
- **Log sources:** Sysmon (Process Creation, Registry Event), Windows Security Event Log (4688, command-line auditing enabled), PowerShell Script Block Logging (4104)
- **SIEM:** Splunk (index: `win1_log`)
- **Execution tool:** Invoke-AtomicRedTeam (`Invoke-AtomicTest`)

## 4. Methodology / Approach

1. Studied the technique (MITRE ATT&CK page) and reviewed available Atomic Red Team tests under T1547.001; selected Test #10 for its use of the HKLM (all-users) Common Startup variant.
2. Formed a baseline hypothesis before execution: expected a Sysmon EventID 13 (registry value set) capturing the `TargetObject` and `Details` fields, with process creation activity dependent on whether execution followed immediately after the registry change.
3. Executed the atomic test via `Invoke-AtomicTest`, noting execution start time: **09/25/2026 1:10:37 PM**. The test required a system reboot to complete.
4. Located the reboot event to anchor the investigation timeline (reboot confirmed at 1:13:18 PM).
5. Initially searched for the expected registry modification event beginning at the reboot timestamp; found no relevant EventID 13 in that window, only Atomic Red Team framework parameter-binding noise.
6. Reassessed the hypothesis: reconsidered whether the registry write occurred *before* the reboot, with the reboot only triggering execution of the redirected Startup contents. Broadened the search window backward to the original execution timestamp.
7. Identified a process creation event (PID 10088, PPID 8128 / `powershell.exe`) containing the full command block performing the directory creation, binary copy, and registry value change — with no corresponding Sysmon EventID 13 confirming the write itself.
8. Cross-validated the command's execution using PowerShell Script Block Logging (EventID 4104), which captured the full `Set-ItemProperty` script block text, confirming the command ran despite the missing Sysmon 13.
9. Confirmed Sysmon EventID 13 was functioning generally for HKLM registry changes (observed for unrelated keys near the same time), ruling out a total HKLM monitoring failure.
10. Reviewed the Sysmon configuration XML directly and located the relevant `RegistryEvent` `onmatch="include"` rule: a condition matching `TargetObject` **"ends with"** `User Shell Folders\Startup` — which does not match the `Common Startup` value, explaining the missing event as a configuration-level coverage gap rather than a PowerShell-specific or general HKLM exclusion.
11. Confirmed post-reboot execution of the planted binary from the redirected Startup path.

## 5. Investigation Findings — Timeline & Process Chain

```
1:10:37 PM  powershell.exe (PID 10088, PPID 8128) runs:
            New-Item        -> creates %TMP%\atomictest\
            Copy-Item       -> copies C:\Windows\System32\calc.exe into that directory
            Set-ItemProperty -> sets HKLM\...\User Shell Folders "Common Startup"
                                to %TMP%\atomictest\
            [No Sysmon EventID 13 logged for this write - detection gap, see below]

1:13:18 PM  System reboot

1:16:43 PM  calc.exe (PID 8840, PPID 2784 / explorer.exe) executes from
            C:\Users\host1\AppData\Local\Temp\atomictest\calc.exe
```

**Corroborating telemetry:** PowerShell Script Block Logging (EventID 4104) captured the full `Set-ItemProperty` command text at the same timestamp as the process creation event, independently confirming the registry write occurred despite the absence of a Sysmon EventID 13 for it.

**Root cause of the missing Sysmon EventID 13:** The Sysmon configuration's `RegistryEvent` `onmatch="include"` rule matches `TargetObject` values ending with `User Shell Folders\Startup` only. Because the modified value name is `Common Startup` rather than `Startup`, it does not satisfy the "ends with" condition and is never logged — a narrowly-scoped include rule that misses this specific (all-users) variant of the technique while still correctly capturing the per-user Startup variant and other unrelated HKLM registry activity.

## 6. Indicators of Compromise (IOCs)

| IOC | Type | Strength | Notes |
|---|---|---|---|
| Behavioral pattern: PowerShell creating a new directory, copying an executable into it, then modifying a `User Shell Folders` registry value to point Startup at that new directory | Behavioral / command pattern | Strong | Survives cosmetic changes (folder name, binary copied, command order); captures the technique's actual mechanics |
| Registry key/value: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, value `Common Startup` | Registry artifact | Strong | The persistence mechanism itself; key path is fixed by Windows regardless of what payload the value is repointed to |
| Non-default binary executing from a user-writable path (e.g., `%TEMP%\...`), spawned by `explorer.exe` immediately following a system reboot | Behavioral / process lineage | Strong | Durable, technique-level pattern for Startup-based persistence; independent of which specific binary is planted |
| High integrity level on the `powershell.exe` process performing the registry write | Contextual / supporting | Supporting only | Not suspicious alone, but this technique requires elevation (HKLM), so it corroborates that elevated access was already obtained |

**Considered and excluded:**
- **ComputerName** — case metadata only; does not distinguish malicious activity or transfer to other hosts/incidents.
- **Exact copied binary (`calc.exe`) as a filename/hash** — benign, common binary; only meaningful through the lineage/location context above.
- **Missing Sysmon EventID 13 for this registry path** — a property of this environment's Sysmon configuration, not of the adversary's behavior; documented under Detection Gaps below rather than as an IOC.

## 7. Lessons Learned / Detection Gaps

- Do not conclude an action did not occur solely because an expected corroborating log event is absent. Command-line/process-creation evidence and alternate telemetry sources (here, PowerShell Script Block Logging) should be checked before ruling an action out — the absence of one event type is not proof of absence of the activity.
- When a technique's completion depends on a system state change (e.g., a reboot), verify the actual order of operations from the technique's own documentation rather than assuming the triggering action occurs after the state change; search both before and after the trigger event.
- Sysmon `onmatch="include"` rules using literal string conditions (e.g., "ends with") can create narrow, variant-specific blind spots. A rule intended to cover Startup folder persistence captured the per-user Startup variant but silently missed the Common Startup (all-users) variant of the same technique.
- This detection gap directly validates the scenario's original hypothesis that an attacker may prefer the "Common" (all-users) variant specifically for broader impact — and in this environment, that variant also carries weaker detection coverage, reinforcing the importance of testing all known variants of a technique rather than only the most commonly documented example.
- Elevated (High) integrity level on a process is not a standalone indicator, but becomes meaningful supporting context when paired with a technique that specifically requires elevation to execute.

## 8. Recommendations

- Broaden the Sysmon `RegistryEvent` `onmatch="include"` condition to also capture `Common Startup` (e.g., matching more broadly on `Shell Folders` or adding an explicit condition for the Common Startup value), and audit the wider config for other similarly narrow "ends with" conditions that may miss related technique variants.
- Build a correlation search for the full behavioral pattern (directory creation + binary copy + Shell Folders registry modification via PowerShell) rather than relying solely on Sysmon EventID 13, correlating EventID 4104 script block content with related process and file creation events.
- Add monitoring for binaries executing from non-default, user-writable paths shortly after a system reboot when spawned by `explorer.exe`, as a detection layer independent of registry event capture.
- Periodically audit Sysmon configuration coverage against the full list of known technique variants rather than validating against a single representative example.
