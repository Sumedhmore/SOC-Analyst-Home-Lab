# Windows SIEM Detection Rules

## Overview

This document contains the Splunk detection rules developed as part of a Windows SIEM home lab.

The lab collects Windows Event Logs using the Splunk Universal Forwarder and analyzes authentication activity in Splunk Enterprise.

---

# Detection 1 — Multiple Failed Windows Logons

## Objective

Detect multiple failed Windows authentication attempts from the same source within a short time period.

This behavior can be associated with password-guessing activity.

## Data Source

* **Log Source:** Windows Security Event Log
* **Event ID:** 4625
* **SIEM:** Splunk Enterprise
* **Index:** `wineventlog`

## Detection Logic

The detection triggers when **3 or more failed logon attempts occur within a one-minute window** from the same source IP and logon type.

## SPL

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

* **Alert Name:** Multiple Failed Windows Logons
* **Alert Type:** Scheduled
* **Schedule:** Every minute
* **Time Range:** Last 5 minutes
* **Trigger Condition:** Number of Results > 0
* **Trigger:** Once
* **Action:** Add to Triggered Alerts

## Lab Result

The detection successfully triggered during the lab after intentionally generating repeated failed Windows logon attempts.

One observed detection contained:

* **Failed attempts:** 4
* **Source IP:** `127.0.0.1`
* **Logon Type:** 2 — Interactive

The activity was intentionally generated for testing and was classified as **Benign / Lab Simulation**.

## MITRE ATT&CK

**T1110.001 — Password Guessing**

The detection logic is aligned with this technique because repeated authentication failures can indicate password-guessing behavior.

---

# Detection 2 — Multiple Failed Logons Followed by Successful Authentication

## Objective

Correlate multiple failed Windows authentication attempts with a subsequent successful authentication.

This provides additional context for investigating whether repeated authentication failures resulted in a successful login.

## Data Sources

* **Event ID 4625:** Failed logon
* **Event ID 4624:** Successful logon
* **Log Source:** Windows Security Event Log
* **SIEM:** Splunk Enterprise
* **Index:** `wineventlog`

## Detection Logic

The query:

1. Extracts Windows Event IDs from the raw event.
2. Filters for Event IDs 4624 and 4625.
3. Extracts the target username, logon type, and source IP.
4. Groups activity by source.
5. Counts recent failed authentication attempts.
6. Identifies successful authentication events following multiple failures.
7. Produces a summarized investigation result.

## SPL

```spl
index=wineventlog
| rex field=_raw "<EventID>(?<EventID>[^<]+)"
| search EventID=4624 OR EventID=4625
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>[^<]+)"
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]+)"
| eval SourceIP=if(IpAddress="-" OR IpAddress="", "LOCAL", IpAddress)
| sort 0 SourceIP _time
| streamstats current=f window=10 count(eval(EventID=4625)) as FailedAttempts by SourceIP
| where EventID=4624 AND FailedAttempts>=3
| stats max(FailedAttempts) as FailedAttempts min(_time) as FirstDetected max(_time) as SuccessfulLogin by SourceIP TargetUserName
| eval FirstDetected=strftime(FirstDetected,"%Y-%m-%d %H:%M:%S")
| eval SuccessfulLogin=strftime(SuccessfulLogin,"%Y-%m-%d %H:%M:%S")
| table FirstDetected SuccessfulLogin SourceIP TargetUserName FailedAttempts
| sort - SuccessfulLogin
```

## Observed Lab Result

The correlation query produced the following result:

| Field            | Value                       |
| ---------------- | --------------------------- |
| First Detected   | `2026-09-30 20:29:39`       |
| Successful Login | `2026-09-30 23:52:41`       |
| Source IP        | `127.0.0.1`                 |
| Target User      | `sumedhmore013@outlook.com` |
| Failed Attempts  | `8`                         |

The underlying event timeline also showed four failed interactive logons between `20:29:23` and `20:29:29`, followed by a successful authentication at `20:29:39`.

## Investigation Findings

The failed events were:

* Event ID **4625**
* Logon Type **2 — Interactive**
* Source IP **127.0.0.1**
* Status `0xc000006d`
* SubStatus `0xc0000380`
* Process `C:\Windows\System32\svchost.exe`

The subsequent successful authentication was recorded as Event ID **4624** with Logon Type **11 — Cached Interactive**.

A Logon Type 7 event was also observed, representing workstation unlock activity.

## Classification

**Benign / Lab Simulation**

The failed authentication attempts were intentionally generated during testing. The evidence therefore demonstrates that the detection and correlation logic works, but does not represent a confirmed real-world attack or account compromise.

## MITRE ATT&CK

**Primary mapping: T1110.001 — Password Guessing**

The detection is designed to identify behavior consistent with password-guessing activity.

The MITRE mapping describes the behavior the detection is intended to detect; it does not establish that an adversary was present in this lab.

---

# Detection Engineering Notes

## Detection Strengths

* Uses Windows Security Event Logs.
* Detects repeated authentication failures.
* Correlates failed and successful authentication.
* Uses a time-based threshold.
* Generates a Splunk alert.
* Provides source IP and authentication context.
* Can be investigated using additional Windows events.

## Potential False Positives

Possible legitimate causes of repeated failed logons include:

* User entering an incorrect password repeatedly.
* Incorrectly configured applications or services.
* Cached or outdated credentials.
* Automated tasks using invalid credentials.
* Administrative activity.

Therefore, the detection should be investigated in context rather than automatically treated as malicious.

## Recommended Investigation Steps

For a real-world alert:

1. Identify the source IP.
2. Identify the targeted account.
3. Determine whether the source is internal or external.
4. Review the number and timing of failed attempts.
5. Correlate Event ID 4625 with Event ID 4624.
6. Review the successful login's logon type.
7. Investigate surrounding Windows Security and System events.
8. Check whether the activity is expected.
9. Escalate or contain the activity if additional evidence indicates compromise.
