# Digital Forensics Log Analyzer

A C++ console application for multi-case digital forensics investigation — built as an Object-Oriented Programming course project for **BSCYS-F-25-B, Department of Cyber Security, Air University**.

The system ingests raw system log files, runs them through a rule-based threat detection engine, and produces structured investigation reports, all wrapped in a multi-user, role-based authentication system.

## Authors

- Abdullah Sajid —



## Features

- **Multi-user authentication** with role-based access control (`admin` / `user`)
- Account registration, login, automatic lockout after 5 failed attempts, and admin unlock
- **Multi-case workspace** — up to 10 simultaneous forensics cases
- **Dual log parser hierarchy** — a `SampleLogParser` for structured demo logs and a `RealLinuxLogParser` for `/var/log/auth.log`-style syslog input
- **8-rule threat detection engine** raising `CRITICAL` and `WARNING` alerts
- On-screen and file-based investigation report generation
- Built-in sample log generator for demos and testing
- Admin control panel for user management (promote, demote, delete, unlock)

## OOP Concepts Demonstrated

| Concept | Where |
|---|---|
| Classes & Objects | `Analyst`, `ForensicCase`, `LogParser` hierarchy |
| Encapsulation | Private members/helpers in `Analyst` and `ForensicCase`, accessed only through public getters and methods |
| Inheritance | `SampleLogParser` and `RealLinuxLogParser` derive from abstract `LogParser` |
| Polymorphism | Runtime dispatch through a `LogParser*` base pointer calling `parseAndLoad()` |
| Constructors / Destructors | Full canonical form (default, parameterized, copy, destructor) in `Analyst` and `ForensicCase`, managing heap memory |
| Static Members | `Analyst::totalAnalysts`, `ForensicCase::caseCounter` |
| Dynamic Memory Management | Manually managed, doubling dynamic arrays for events/alerts (no `std::vector`) instead of fixed-size containers |
| Const Correctness | Getters and report-printing marked `const`; `caseID` is `const`, set only via the member-initializer list |
| Union | `EventSource` stores either an IP address or a hostname, paired with a `bool` discriminator for safe access |

## Core Classes & Data Structures

| Type | Role |
|---|---|
| `Analyst` | Models an investigator/admin — name, badge ID, role, `isAdmin()` |
| `ForensicCase` | Models a single investigation — owns events, alerts, runs analysis, generates reports |
| `LogParser` (abstract) | Defines the parser interface via pure virtual `parseAndLoad()` |
| `SampleLogParser` | Parses `[timestamp] EVENT key=value` formatted sample logs |
| `RealLinuxLogParser` | Parses Linux `auth.log` syslog-style lines |
| `RawEvent` (struct) | A single parsed log entry (timestamp, event type, username, detail, severity, hour) |
| `Alert` (struct) | A raised threat alert (type, description, severity tier, timestamp) |
| `EventSource` (union) | Either an IP address or a hostname for a case's source |
| `UserAccount` (struct) | Username, password hash (plain-text in this build), role, locked flag |

## Threat Detection Rules

The analysis engine scans all loaded events and applies 8 independent rules, with de-duplication so the same alert isn't raised twice:

| # | Alert Type | Tier | Trigger |
|---|---|---|---|
| 1 | `BRUTE_FORCE` | CRITICAL | 3+ `LOGIN_FAILED` events for the same user |
| 2 | `SUCCESSFUL_BRUTE_FORCE` | CRITICAL | `LOGIN_SUCCESS` preceded by 3+ `LOGIN_FAILED` for the same user |
| 3 | `SENSITIVE_FILE_ACCESS` | CRITICAL | `FILE_ACCESS` targeting `/etc/passwd`, `/etc/shadow`, SAM, or `id_rsa` |
| 4 | `REPEATED_FILE_ACCESS` | WARNING | Same file accessed 3+ times |
| 5 | `SUSPICIOUS_COMMAND` | WARNING | `CMD_EXEC` containing `whoami`, `mimikatz`, `powershell`, `curl`, or `net_user` |
| 6 | `PRIVILEGE_ESCALATION` | CRITICAL | Any `PRIV_ESCALATION` event |
| 7 | `SUSPICIOUS_LOGIN_TIME` | WARNING | Login/escalation activity between 00:00–04:59 |
| 8 | `PORT_SCAN` | WARNING | 5+ `PORT_SCAN` events |

**Verdict** is computed from the resulting alert mix:

| Condition | Verdict |
|---|---|
| 2+ CRITICAL alerts | HIGH RISK |
| 1 CRITICAL, or 3+ WARNING alerts | MEDIUM RISK |
| 1+ WARNING alert | LOW RISK |
| No alerts | CLEAN |

## Role-Based Access

| Feature | Admin | User |
|---|---|---|
| Create New Case | ✅ | ❌ |
| Load Log File | ✅ | ✅ |
| Run Analysis | ✅ | ✅ |
| Print / Save Report | ✅ | ✅ |
| Generate Sample Log | ✅ | ❌ |
| User Management Panel | ✅ | ❌ |
| Switch / View / Delete / Deselect Case | ✅ | ✅ |

Login allows up to 5 password attempts before automatic lockout. The 4 hardcoded core admin accounts can never be locked, deleted, or demoted.

## File I/O

| File | Purpose | Format |
|---|---|---|
| `users.txt` | Persists non-admin accounts across sessions | CSV: `username,password,role,locked(0/1)` |
| `<name>.log` | Input log file for analysis | Sample format or Linux `auth.log` syslog format |
| `<report>.txt` | Output investigation report | Formatted plain-text report |

The parser is auto-selected based on the filename: if it contains `"Linux"`, `RealLinuxLogParser` is used; otherwise `SampleLogParser` is used.

## Building

The project is a single `.cpp` translation unit with no external dependencies beyond the C++ standard library.

```bash
g++ -std=c++17 -o forensics_analyzer main.cpp
./forensics_analyzer
```

(On Windows with MSVC, just build the `.cpp` file as a console application — `_CRT_SECURE_NO_WARNINGS` is already defined at the top of the file.)

## Running

1. On first launch, choose **1. Login** or **2. Register**.
2. Default hardcoded admin accounts exist out of the box (see `ADMIN_NAMES` / `ADMIN_PLAIN_PASSWORDS` in the source) — these are intended for demo/grading use only.
3. As admin, create a new case, then use **Generate Sample Log** to produce a demo log file, or load a real `auth.log`-style file.
4. Run analysis on the active case to raise alerts and compute a verdict.
5. Print the report to screen or save it to a `.txt` file.

## Sample Report Output

```
=======================================================================
                       DIGITAL FORENSICS CASE REPORT
=======================================================================
Case ID      : 2
Title        : Sample Linux Log File
Source       : 192.111.222.333
Investigator : abdullah (Badge #1234)
-----------------------------------------------------------------------
Events Parsed : 20
Alerts Raised : 16
-----------------------------------------------------------------------
[1] BRUTE_FORCE [CRITICAL]
    Threshold breached: Total 3 auth failures detected for user: root
    Time: May 31 17:36:55
...
-----------------------------------------------------------------------
VERDICT : HIGH RISK
=======================================================================
```

## Design Decisions

- Dynamic arrays with a doubling-capacity strategy are used in place of `std::vector`, to satisfy the manual memory management requirement of the OOP course.
- `EventSource` is implemented as a `union` (paired with a `bool sourceIsIP` flag) to model "either an IP or a hostname" at the language level, even though both members are the same size.
- The `LogParser` hierarchy uses a pure virtual `parseAndLoad()`, forcing every derived parser to implement the interface — adding a new log format requires only a new derived class, with no changes to client code.
- `ForensicCase::caseCounter` is a static class member, guaranteeing unique sequential case IDs without external bookkeeping.
- Core admin credentials are hardcoded at compile time so the system always has at least one valid admin account, even if `users.txt` is missing or corrupted.

## Known Limitations

- **Passwords are stored and compared in plain text.** `hashPassword()` is currently a pass-through; a production build should use a cryptographic hash (e.g. SHA-256 or bcrypt).
- Maximum case capacity is hardcoded at 10; this could be made dynamic.
- `RealLinuxLogParser` only handles a subset of `auth.log` patterns — full syslog coverage would need a more comprehensive parser.
- `users.txt` is stored unencrypted and is readable as plain text.
- The brute-force rule counts failures globally rather than within a time window, which could produce false positives over long-running logs.

## Possible Extensions

- Live log ingestion over network sockets
- Cryptographic password hashing
- A database backend for persistent case storage
- A graphical user interface
