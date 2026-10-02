# Detection Engineering

## Detection 1 — Multiple Failed Windows Logons

### Objective

Detect repeated failed Windows authentication attempts occurring within a short time period.

The detection looks for Windows Event ID **4625**, groups events into one-minute windows, and identifies windows containing three or more failed logons.

### SPL

```spl
index=wineventlog 4625
| rex field=_raw "<Data Name=\"IpAddress\">(?<IpAddress>[^<]+)"
| rex field=_raw "<Data Name=\"LogonType\">(?<LogonType>[^<]+)"
| bin _time span=1m
| stats count as Failed_Logins by _time IpAddress LogonType
| where Failed_Logins >= 3
| sort - _time
```

### Query Breakdown

**`index=wineventlog 4625`**

Searches the `wineventlog` index for Windows Event ID **4625**, which represents a failed logon.

**`rex field=_raw`**

Extracts fields from the original raw Windows event because the required fields were not automatically extracted by Splunk.

The detection extracts:

* `IpAddress`
* `LogonType`

**`bin _time span=1m`**

Groups events into one-minute time buckets.

**`stats count as Failed_Logins`**

Counts the number of failed logon events in each time window.

**`where Failed_Logins >= 3`**

Keeps only time windows containing three or more failed logon events.

### Observed Lab Result

The controlled lab simulation produced the following detection result, verified in `01-bruteforce-detection.png`:

| Time Window         | Source IP | Logon Type | Failed Logins |
| ------------------- | --------- | ---------: | ------------: |
| 2026-10-02 17:50:00 | 127.0.0.1 |          2 |             4 |

---

# Detection 2 — Failed Authentication Investigation

After identifying repeated failures, additional Windows authentication fields were extracted for investigation.

### SPL

```spl
index=wineventlog 4625
| rex field=_raw "<Data Name=\"IpAddress\">(?<IpAddress>[^<]+)"
| rex field=_raw "<Data Name=\"LogonType\">(?<LogonType>[^<]+)"
| rex field=_raw "<Data Name=\"Status\">(?<Status>[^<]+)"
| rex field=_raw "<Data Name=\"SubStatus\">(?<SubStatus>[^<]+)"
| table _time host IpAddress LogonType Status SubStatus
| sort - _time
```

### Investigated Fields

| Field       | Purpose                                                   |
| ----------- | --------------------------------------------------------- |
| `_time`     | Time of the authentication failure                        |
| `host`      | Windows system generating the event                       |
| `IpAddress` | Source address associated with the authentication attempt |
| `LogonType` | Type of Windows authentication                            |
| `Status`    | Authentication failure status                             |
| `SubStatus` | More specific authentication status                       |

### Observed Values

The controlled lab events showed:

* **Host:** `Kakarot`
* **Source IP:** `127.0.0.1`
* **Logon Type:** `2`
* **Status:** `0xc000006d`
* **SubStatus:** `0xc0000380`

### Interpretation

`127.0.0.1` indicates that the authentication activity originated locally from the Windows machine.

Logon Type `2` represents an interactive logon, which is consistent with the Windows login interface used during the lab simulation.

The observed status values indicate that authentication failed.

Because the events were intentionally generated on the analyst's own Windows machine, the activity was classified as a **Benign / Controlled Lab Simulation**.

---

# Alert Configuration

### Alert Name

`Windows Brute Force - Multiple Failed Logons`

### Description

Detects 3 or more failed Windows interactive logon attempts from the same source IP within a one-minute window.

### Configuration

| Setting           | Configuration                    |
| ----------------- | -------------------------------- |
| Alert Type        | Scheduled                        |
| Schedule          | Every minute                     |
| Search Window     | Last 5 minutes                   |
| Severity          | Medium                           |
| Mode              | Digest                           |
| Trigger Condition | Number of results greater than 0 |
| Trigger           | Once                             |
| Action            | Add to Triggered Alerts          |
| Sharing           | Private                          |
| Status            | Enabled                          |

### Alert Validation

The alert was tested by intentionally generating multiple incorrect Windows login attempts.

The alert successfully appeared under **Splunk → Activity → Triggered Alerts**.

---

# Detection Limitations

This detection is intentionally simple and designed for a beginner SOC lab.

Potential limitations include:

* Legitimate users repeatedly entering incorrect passwords may trigger the detection.
* Local authentication failures can produce `127.0.0.1`.
* A one-minute threshold may not detect slower password-guessing activity.
* The detection does not independently prove malicious activity.
* Additional correlation with successful logons, accounts, source systems, and other security events would improve confidence.

---

# MITRE ATT&CK

**Technique:** T1110 — Brute Force

The detection is associated with the **Brute Force** technique because it identifies repeated authentication failures.

The MITRE mapping represents the behavior being detected and does not mean that the lab activity was an actual attack.
