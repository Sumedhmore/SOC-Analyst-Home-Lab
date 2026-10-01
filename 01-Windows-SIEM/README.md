# Windows SIEM Threat Detection Lab

## Overview

This project is a hands-on Security Operations Center (SOC) home lab built to practice Windows security monitoring, SIEM-based detection, alerting, investigation, and incident analysis.

Windows Event Logs are collected using the Splunk Universal Forwarder and forwarded to Splunk Enterprise running inside a Kali Linux virtual machine.

The lab focuses on authentication-related security events and demonstrates how a SOC analyst can identify repeated failed logons, correlate authentication events, investigate alerts, and document findings.

---

## Lab Architecture

```text
Windows 11 Host
     │
     │ Splunk Universal Forwarder
     │
     │ Windows Security/System/Application Logs
     ▼
VirtualBox Bridged Network
     │
     ▼
Kali Linux VM
     │
     │ Splunk Enterprise
     │ Receiving Port: 9997
     ▼
wineventlog Index
     │
     ▼
Splunk Search & Detection
     │
     ├── Failed Logon Detection
     ├── Authentication Correlation
     └── Triggered Alerts
```

---

## Technologies Used

* Windows 11
* Kali Linux
* Oracle VirtualBox
* Splunk Enterprise
* Splunk Universal Forwarder
* Windows Event Viewer
* Windows Security Event Logs
* SPL (Splunk Search Processing Language)
* MITRE ATT&CK

---

## Data Collection

Windows Event Logs are collected using the Splunk Universal Forwarder.

The following Windows log sources are monitored:

* Security
* System
* Application

The logs are stored in the Splunk index:

```text
wineventlog
```

Splunk Enterprise receives the forwarded events on:

```text
TCP 9997
```

---

## Windows Security Events Investigated

The project focuses primarily on authentication-related Windows Security Events.

| Event ID | Description                              |
| -------- | ---------------------------------------- |
| 4624     | Successful logon                         |
| 4625     | Failed logon                             |
| 4672     | Special privileges assigned to new logon |
| 4688     | New process created                      |
| 4720     | User account created                     |
| 4728     | User added to a global security group    |
| 4732     | User added to a local security group     |
| 1102     | Audit log was cleared                    |

Not every event above was used to generate a detection in this stage. They are included as part of the broader Windows security monitoring scope of the lab.

---

# Detection 1 — Multiple Failed Windows Logons

## Objective

Detect repeated failed Windows authentication attempts within a short time period.

The detection identifies three or more failed logons within a one-minute window from the same source and logon type.

## Event

```text
Event ID: 4625
```

## Detection Logic

```spl
index=wineventlog 4625
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]+)"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>[^<]+)"
| bin _time span=1m
| stats count as Failed_Logins by _time, IpAddress, LogonType
| where Failed_Logins >= 3
| sort - _time
```

## Alert Configuration

* Alert Name: `Multiple Failed Windows Logons`
* Alert Type: Scheduled
* Schedule: Every minute
* Time Range: Last 5 minutes
* Trigger Condition: Number of Results > 0
* Trigger: Once
* Action: Add to Triggered Alerts

## Lab Result

The alert successfully triggered after repeated failed logon attempts were intentionally generated on the Windows host.

Example detection:

```text
Failed Attempts: 4
Source IP: 127.0.0.1
Logon Type: 2
```

The activity was intentionally generated as part of the lab and was classified as:

```text
Benign / Lab Simulation
```

---

# Detection 2 — Failed Logons Followed by Successful Authentication

## Objective

Correlate multiple failed authentication attempts with a subsequent successful authentication.

This provides additional context during authentication investigations.

## Events

```text
4625 → Failed Logon
4624 → Successful Logon
```

## Detection Approach

The detection:

1. Extracts the Windows Event ID.
2. Filters for Event IDs 4624 and 4625.
3. Extracts username, logon type, and source IP.
4. Groups activity by source.
5. Counts recent failed authentication attempts.
6. Identifies successful authentication following multiple failures.
7. Summarizes the resulting activity.

## Result

During the lab, the underlying event timeline showed:

```text
4625 → Failed Logon
4625 → Failed Logon
4625 → Failed Logon
4625 → Failed Logon
        ↓
4624 → Successful Authentication
```

The failed events were generated intentionally for detection testing.

---

# Investigation Findings

The observed failed authentication events contained:

| Field      | Observed Value                    |
| ---------- | --------------------------------- |
| Event ID   | 4625                              |
| Logon Type | 2 — Interactive                   |
| Source IP  | 127.0.0.1                         |
| Status     | 0xc000006d                        |
| SubStatus  | 0xc0000380                        |
| Process    | `C:\Windows\System32\svchost.exe` |

A subsequent successful authentication was also observed as Event ID 4624.

The successful authentication included Logon Type 11, representing cached interactive authentication.

A Logon Type 7 event was also observed, representing workstation unlock activity.

---

# MITRE ATT&CK Mapping

## T1110.001 — Password Guessing

The repeated failed authentication detection is aligned with:

```text
T1110.001 — Password Guessing
```

This mapping describes the behavior the detection is designed to identify.

The lab activity itself was intentionally generated and does not establish the presence of an attacker or account compromise.

---

# Alert Investigation Workflow

The investigation workflow used in this project is:

```text
Windows Event
      ↓
Splunk Universal Forwarder
      ↓
Splunk Enterprise
      ↓
Search / SPL Detection
      ↓
Alert Triggered
      ↓
Review Event Details
      ↓
Correlate Authentication Events
      ↓
Determine Context
      ↓
Classify Activity
      ↓
Document Findings
```

---

# False Positives

Repeated failed logons do not automatically indicate malicious activity.

Possible legitimate causes include:

* User entering an incorrect password.
* Incorrectly configured applications.
* Outdated credentials.
* Automated tasks using invalid credentials.
* Cached credentials.
* Administrative activity.

Therefore, authentication alerts should be investigated in context.

---

# Evidence

The following screenshots document the lab:

### 1. Failed Logon Events

Shows Windows Event ID 4625 events collected in Splunk.

```text
screenshots/01-4625-failed-logins.png
```

### 2. Triggered Alert

Shows the `Multiple Failed Windows Logons` alert appearing in Splunk's Triggered Alerts.

```text
screenshots/02-triggered-alert.png
```

### 3. Authentication Correlation

Shows the correlation between failed and successful authentication events.

```text
screenshots/03-4625-to-4624-correlation.png
```

---

# Project Outcome

This project demonstrates the basic workflow of a SOC analyst working with a Windows-based SIEM environment.

The lab successfully demonstrates:

* Windows Event Log collection.
* Splunk Universal Forwarder configuration.
* Splunk Enterprise log ingestion.
* Windows authentication monitoring.
* SPL-based detection development.
* Scheduled alert creation.
* Alert validation.
* Authentication event correlation.
* MITRE ATT&CK mapping.
* Basic security investigation.
* Security finding documentation.

---

# Future Improvements

Potential improvements for future versions of the lab include:

* Detecting suspicious PowerShell activity.
* Monitoring process creation events.
* Detecting account creation.
* Monitoring privilege escalation events.
* Adding additional correlation rules.
* Creating Splunk dashboards.
* Integrating network traffic analysis.
* Building a basic SOC case-management workflow.

---

## Disclaimer

This is a personal cybersecurity learning lab.

The authentication events and suspicious-looking activity documented in this project were intentionally generated for testing and educational purposes.

No real-world attack or compromised account is being claimed.
