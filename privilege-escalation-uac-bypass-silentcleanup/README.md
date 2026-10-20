# Privilege Escalation – UAC Bypass via SilentCleanup Task

**MITRE ATT&CK:** [T1548.002 – Abuse Elevation Control Mechanism: Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002/)

> **Outcome: technique attempted but unsuccessful in this environment.** The investigation value of this scenario is in proving *why* it failed, end-to-end, using native OS diagnostics in addition to the SIEM.

## 1. Objective / Scope

Simulate and investigate a Windows User Account Control (UAC) bypass technique using Atomic Red Team, with the goal of practicing multi-source telemetry correlation (Sysmon, Splunk, and native OS diagnostic tools), verifying whether a simulated technique actually achieved its objective rather than assuming success, and identifying detection coverage gaps.

## 2. Technique Overview

| Field | Detail |
|---|---|
| Tactic | Privilege Escalation (TA0004) |
| Technique | T1548.002 – Abuse Elevation Control Mechanism: Bypass User Account Control |
| Atomic Test | Test #9: "Bypass UAC using SilentCleanup task" |
| Mechanism | Sets `HKCU\Environment` value `windir` to `cmd /c start powershell&REM `, then forcibly triggers the built-in, auto-elevated `SilentCleanup` scheduled task via `schtasks /run`. Because the task's action path (`%windir%\system32\cleanmgr.exe`) is expanded using the hijacked `windir` value, the intent is for the task's elevated context to launch the attacker-controlled command instead of `cleanmgr.exe`, with `REM` commenting out the remainder of the original path. |

**Privilege note:** Targets HKCU (user-writable, no elevation required to set), exploiting the fact that the SilentCleanup task itself is configured to run at `HighestAvailable` privilege for the Authenticated Users group — the technique's value lies in escalating *from* a non-elevated context, not in requiring one.

## 3. Environment

- **Victim host:** Windows VM (host1)
- **Log sources:** Sysmon (Process Creation, Registry Event), Windows Security Event Log (4688, command-line auditing enabled), PowerShell Script Block Logging (4104), Task Scheduler Operational log (local, not forwarded to Splunk)
- **SIEM:** Splunk (index: `win1_log`)
- **Execution tool:** Invoke-AtomicRedTeam (`Invoke-AtomicTest`)

## 4. Methodology / Approach

1. Studied the technique (MITRE ATT&CK page) and reviewed Atomic Red Team tests under T1548.002; selected Test #9. Researched the SilentCleanup task's auto-elevation behavior and read the test's executor command directly rather than relying on the general technique description.
2. Formed a baseline hypothesis before execution: expected Sysmon EventID 13 (registry value set) and EventID 1 (process creation) leading to an elevated process, while recognizing that running the test from an already-elevated PowerShell session would make the registry write also show High integrity in this lab — not a reliable signal on its own.
3. Resolved a missing test prerequisite (the test's `.bat` file was not present in the local atomics `src` folder and had to be retrieved manually from the official Atomic Red Team repository) before proceeding.
4. Executed the atomic test, noting the on-screen message: *"The screen cannot be set to the number of lines and columns specified. The operation completed successfully."* Noted execution start time: **09/28/2026 3:30:31 PM**.
5. Investigated in Splunk: filtered known Atomic Red Team framework noise, then reconstructed each line of the batch script from CommandLine field evidence, correctly explaining the console-resize, registry hijack, forced task trigger, and cleanup steps.
6. Identified a discrepancy between the source script and the logged CommandLine (a missing `>nul` redirection); researched and resolved it as an artifact of batch-line execution rather than suppressed logging — consistent with the lesson from the Execution scenario (batch-file built-ins and redirection operators interpreted by an already-running `cmd.exe` do not generate separate Sysmon process-creation events).
7. Checked the Sysmon configuration for `RegistryEvent` coverage of `HKCU\Environment` and found it absent from both include and exclude rule sets, explaining the missing EventID 13 entries as a coverage gap.
8. Searched broadly for any resulting elevated process with no results, then verified the technique's actual outcome using native OS diagnostic tooling (`schtasks` run history, Task Scheduler Operational log with history enabled) rather than relying on SIEM telemetry alone, decoding the resulting error codes and reviewing the task's permission configuration to determine the root cause of the failure.

## 5. Investigation Findings — Timeline & Outcome

```
powershell.exe (PPID 6368)
  └─ cmd.exe (PID 5444) executes T1548.002.bat
       ├─ mode 18,1
       │    -> console resize attempt (produced on-screen "screen cannot
       │       be set..." message); obscuring attempt
       ├─ reg add "HKCU\Environment" /v "windir" /d "cmd /c start powershell&REM "
       │    -> hijacks windir; [No Sysmon EventID 13 - detection gap]
       ├─ timeout /t 2
       ├─ schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
       │    -> forces on-demand execution of the auto-elevated task
       │    -> Task Scheduler attempts to launch action (hijacked
       │       %windir%\system32\cleanmgr.exe path)
       │    -> FAILS: EventID 101 + 203 (Task Scheduler Operational log)
       │       embedded error 0x80070002 (ERROR_FILE_NOT_FOUND)
       │    -> schtasks Last Result: 0x800710E0 ("operator/administrator
       │       refused the request")
       │    -> No resulting elevated process found (Sysmon 1 + Security
       │       4688, broad time window - confirmed absence)
       ├─ timeout /t 3
       └─ reg delete "HKCU\Environment" /v "windir" /F
            -> cleanup/anti-forensic step; [No Sysmon EventID 13 - same gap]
```

**Outcome:** Technique attempted, not successful. The registry hijack was written correctly per its own logic, and the forced task trigger command executed, but the scheduled task's action-launch mechanism failed to resolve the hijacked value into a running elevated process. No privilege escalation was achieved in this lab environment.

**Root cause of the missing Sysmon EventID 13 (registry set and delete):** The Sysmon configuration's `RegistryEvent` rules do not reference `HKCU\Environment` in either the include or exclude rule sets, so neither the `windir` set nor its later deletion generated an EventID 13 — the same class of narrow registry-coverage gap identified in the Persistence scenario, here affecting a different hive and path.

**Reason for the execution failure:** The task's Action Command field (`%windir%\system32\cleanmgr.exe`) is resolved by the Task Scheduler service at launch time. When manually run, `cmd.exe` correctly interprets the hijacked `windir` value's shell operators (`&` and `REM`). However, the Task Scheduler's action-launch mechanism returned `ERROR_FILE_NOT_FOUND`, consistent with it attempting to resolve the fully expanded string as a literal executable path rather than passing it through shell interpretation the way a manually-invoked `cmd.exe` session would. This distinction — between how a value behaves under direct shell execution versus under a service-driven launch — is the most likely explanation, though it is not confirmed as a documented Microsoft mitigation. The task's own XML (`Principal` GroupId `S-1-5-32-545` / built-in Users, `RunLevel` `HighestAvailable`, with Authenticated Users granted read/execute) showed a permission model that should permit on-demand triggering, indicating the refusal occurs at runtime rather than from a static permissions misconfiguration.

## 6. Indicators of Compromise (IOCs)

| IOC | Type | Strength | Notes |
|---|---|---|---|
| `HKCU\Environment` value `windir` set to a value containing `cmd` and `REM` | Registry artifact / behavioral pattern | Strong | Technique-defining artifact; this shell-hijack shape is specific to this bypass class regardless of whether it ultimately succeeds |
| On-demand forced trigger of an auto-elevated system task via `schtasks /run ... /I` | Behavioral | Strong | Distinguishes malicious manual triggering from the task's normal low-disk-space trigger condition; durable regardless of which auto-elevated task is targeted |
| Create-then-delete of the same registry value within a short window (seconds) | Behavioral pattern | Strong | Anti-forensic cleanup pattern; short-lived registry artifacts are a reusable indicator across many techniques |
| `cmd.exe` executing a `.bat` file that issues a console-resize (`mode`) command immediately before a registry modification | Behavioral / lineage | Moderate | Console-hiding paired with a registry hijack and forced task trigger forms a suspicious combination; `mode` alone is not remarkable |

**Considered and excluded:**
- **Integrity level of the initiating `powershell.exe`/`cmd.exe`** — unlike the Persistence scenario, this write targets HKCU, which does not require elevation. High integrity here is an artifact of how the test was launched, not a meaningful signal, since the technique's premise is escalating from a non-elevated context.
- **A resulting elevated process** — none exists to characterize, since the technique did not succeed. Stated explicitly as a negative finding rather than left as an implied gap.

## 7. Lessons Learned / Detection Gaps

- Individual lines within a batch file, interpreted by the same already-running `cmd.exe` process, do not generate separate Sysmon process-creation events for built-ins or redirection operators (e.g., `>nul`). This explained an apparent discrepancy between the source script and the logged CommandLine.
- Sysmon `RegistryEvent` coverage gaps are not limited to HKLM paths (as found in the Persistence scenario) — `HKCU\Environment` was also absent from this environment's include/exclude rules, missing both the registry hijack and its cleanup deletion.
- An absent expected downstream event should be investigated from multiple angles (widened time window, removal of parent-image assumptions, independent log sources) before concluding either "it didn't happen" or "it's a logging gap." Here the correct conclusion was neither — it was genuine execution failure, confirmed only by consulting native OS diagnostic tooling independently of Sysmon and Splunk.
- A technique's static permission configuration (task XML, security descriptors) can appear fully permissive on paper while the technique still fails at runtime due to how the OS resolves and launches the action.
- Task Scheduler's own history/diagnostic logging (Operational log with "All Tasks History") is disabled by default and should not be assumed available during an investigation; it had to be enabled mid-investigation to obtain the detailed failure codes.
- Lab/tooling prerequisites should be verified before execution. This atomic test defines no automated prerequisite retrieval, requiring the supporting `.bat` file to be manually sourced from the official repository.

## 8. Recommendations

- Broaden Sysmon `RegistryEvent` include coverage to capture `HKCU\Environment`, in addition to the Common Startup gap identified previously, and audit for other commonly-abused environment-variable or shell-hijack-relevant registry paths.
- Enable "All Tasks History" in Task Scheduler as a monitored-host baseline configuration, so task action successes and failures are consistently available in the Operational log.
- Build detection logic around the creation (and especially rapid creation-then-deletion) of environment-variable registry values referencing shell interpreters (`cmd`, `powershell`), since this setup step is a reliable, technique-defining artifact even when the resulting elevated process does not materialize.
- Do not treat this specific UAC bypass method as permanently non-viable based on a single failed run; periodically re-test as OS updates are applied, since the underlying cause appears tied to how this OS build's Task Scheduler resolves the action path rather than a confirmed, documented patch.
- Monitor and alert on forced, on-demand triggering of privileged auto-elevated scheduled tasks (`schtasks /run` against system task paths such as `\Microsoft\Windows\DiskCleanup\`) as a distinct behavioral indicator, independent of whether the subsequent payload succeeds.
