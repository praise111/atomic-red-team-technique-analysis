# Execution – Command Shell Script Write-and-Execute

**MITRE ATT&CK:** [T1059.003 – Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)

## 1. Objective / Scope

Simulate and investigate a Windows Command Shell execution technique using Atomic Red Team, with the goal of practicing log-based process lineage reconstruction and distinguishing test-framework noise from actual simulated adversary behavior, using Splunk as the SIEM.

## 2. Technique Overview

| Field | Detail |
|---|---|
| Tactic | Execution (TA0002) |
| Technique | T1059.003 – Command and Scripting Interpreter: Windows Command Shell |
| Atomic Test | "Command prompt writing script to file then executes it" |
| Description (per source YAML) | Simulates DarkGate malware's second stage by writing a VBScript to disk directly from the command prompt, then executing it. The script runs `whoami` and exits. |
| Elevation required | Yes (`elevation_required: true`) |

**Classification note:** The test is tagged solely as T1059.003 in its source metadata, despite the payload executing via `wscript.exe` (associated with VBScript / T1059.005). No secondary technique tag is applied — an observed limitation in technique classification granularity.

## 3. Environment

- **Victim host:** Windows VM (host1)
- **Log sources:** Sysmon (Process Creation, File Creation), Windows Security Event Log (4688, command-line auditing enabled), PowerShell Script Block Logging (4104) and Module Logging (4103)
- **SIEM:** Splunk (index: `win1_log`)
- **Execution tool:** Invoke-AtomicRedTeam (`Invoke-AtomicTest`)

## 4. Methodology / Approach

1. Studied the technique (MITRE ATT&CK page) and reviewed available Atomic Red Team tests under T1059.003 prior to execution.
2. Formed a baseline hypothesis before execution: expected a file creation event (uncertain whether new file or write to existing file) followed by a process creation event for script execution.
3. Executed the atomic test via `Invoke-AtomicTest`, noting execution window: **9/24/2026 4:30:17 PM – 4:30:19 PM**.
4. Located technique execution metadata in a locally generated CSV log confirming the execution timeframe.
5. Filtered known Atomic Red Team framework noise (`TaskCategory="PowerShell Console Startup"`).
6. Identified and initially misattributed an early `hostname.exe`/`whoami.exe` pair (parent: `powershell.exe`, PID 8128) as possible reconnaissance activity; subsequently confirmed via review of the Atomic Red Team test wrapper script that this pair originates from the framework's own environment-context capture (`$targetHostname = hostname`, `$targetUser = whoami`) — not part of the simulated technique payload.
7. Traced the actual technique payload through process lineage using ProcessId/ParentProcessId fields rather than inferring relationships from command-line text alone, resolving an initial misreading of nested `cmd.exe` invocations within a single command-line string.
8. Verified integrity level on key processes (Sysmon `IntegrityLevel` field) given the test's elevation requirement.

## 5. Investigation Findings — Process Chain

Confirmed chain (validated via ProcessId/ParentProcessId, not command-line text alone):

```
powershell.exe (PID 8128)
  └─ cmd.exe (PID 2960) — writes AtomicTest.vbs via built-in `echo` redirect; invokes it
       ├─ cmd.exe (PID 1616) — runs isolated `cd /d %TEMP%\`; dead-end, no lasting effect
       └─ wscript.exe (PID 7776) — executes AtomicTest.vbs
            └─ whoami.exe (PID 4936)
```

**Key correction made during investigation:** The original command line for PID 2960 contained a nested reference to `c:\windows\system32\cmd.exe`, initially misread as evidence of a distinct "outer/inner" cmd.exe relationship. Verification of the `Image` field on PID 2960 (`C:\Windows\System32\cmd.exe`) and the `&`-delimited structure of the command line confirmed PID 2960 executed the echo-to-file and file invocation directly (as `cmd.exe` built-ins), while only the first `&`-delimited segment (`cmd.exe /c cd /d %TEMP%\`) was spawned as a separate child process (PID 1616), which had no downstream effect.

**File artifact:** `C:\Users\host1\AppData\Local\Temp\AtomicTest.vbs` created by PID 2960 (Sysmon EventID 11).

**Integrity level:** `High`, confirmed on relevant processes, consistent with the test's `elevation_required: true` metadata.

## 6. Indicators of Compromise (IOCs)

| IOC | Type | Strength | Notes |
|---|---|---|---|
| `cmd.exe` → `wscript.exe` → shell command (e.g. `whoami.exe`) process lineage | Behavioral / lineage | Strong | Durable across filename/argument changes; anomalous in most environments |
| Command-line pattern: `echo ... CreateObject("WScript.Shell") ... > *.vbs` followed by immediate execution of that file | Behavioral / command-line pattern | Strong | Technique-level pattern, suitable basis for a correlation search |
| `AtomicTest.vbs` dropped to `%TEMP%\` | File artifact | Weak (test-specific) | Default test parameter; a real actor would likely use a different/randomized filename |
| High integrity level on `cmd.exe` / `wscript.exe` | Contextual | Supporting only | Indicates elevated privilege context; not an indicator on its own |
| Standalone `whoami.exe` execution | Weak in isolation | Not a standalone IOC | Only meaningful in context of the lineage above it |

## 7. Lessons Learned

- Command-line **text** describes intent; only ProcessId/ParentProcessId fields confirm actual process creation. A command line referencing a program name does not necessarily indicate a new process was spawned (e.g., `cmd.exe` built-ins like `echo`, `cd` execute in-process; `&`-chained external program names may or may not spawn children depending on shell parsing).
- Test/tooling artifacts (e.g., Atomic Red Team's own environment-capture commands) can closely resemble adversary reconnaissance behavior and must be distinguished from the actual simulated payload by tracing lineage back to its true origin.
- ATT&CK technique tagging on a given test may not reflect every interpreter or sub-technique actually involved in execution — technique boundaries in practice are fuzzier than matrix categorization suggests.
- Process lineage is generally a stronger, more durable detection indicator than filenames or exact command text, as it is harder for an adversary to obfuscate.

## 8. Recommendations

- Build a Splunk correlation search targeting the `cmd.exe`-writes-`.vbs`-then-executes pattern (echo + redirect to `.vbs` + immediate invocation) rather than relying on the specific filename.
- Extend monitoring/alerting to flag `wscript.exe`/`cscript.exe` spawned as a child of `cmd.exe`, particularly when that lineage subsequently spawns discovery-oriented binaries (`whoami.exe`, `hostname.exe`, `net.exe`, etc.).
- When classifying detections against ATT&CK, consider tagging by all interpreters/binaries actually observed in the execution chain, not solely the tool's listed technique ID.
