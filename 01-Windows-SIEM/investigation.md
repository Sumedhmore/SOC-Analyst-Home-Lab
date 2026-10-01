# Windows Failed Logon Investigation

## 1. Investigation Summary

A Splunk detection was used to identify repeated Windows authentication failures (Event ID 4625) and correlate them with subsequent successful authentication events (Event ID 4624).

The activity was generated intentionally as part of a controlled SOC home-lab simulation to test detection and investigation capabilities.

**Final verdict:** Benign / Lab Simulation

---

## 2. Detection

**Detection name:** Multiple Failed Windows Logons

**Detection logic:**

The detection identifies 3 or more Windows Event ID 4625 failures from the same source within a one-minute time window.

A second correlation query investigates whether a successful Event ID 4624 occurs after multiple failed authentication attempts.

**MITRE ATT&CK:** T1110.001 — Password Guessing

---

## 3. Observed Evidence

The Windows Security logs contained multiple Event ID 4625 failures.

The observed failed authentication events consistently contained:

| Field          | Observed Value                  |
| -------------- | ------------------------------- |
| Event ID       | 4625                            |
| Logon Type     | 2 — Interactive                 |
| Source IP      | 127.0.0.1                       |
| Failure Reason | %%2304                          |
| Status         | 0xc000006d                      |
| SubStatus      | 0xc0000380                      |
| Process        | C:\Windows\System32\svchost.exe |
| Target User    | `-`                             |

Multiple bursts of failed authentication were observed during the lab:

* **20:29:23 – 20:29:29:** 4 failed attempts
* **21:58:55 – 21:59:01:** 3 failed attempts
* **23:12:30 – 23:12:36:** 3 failed attempts
* **23:38:12 – 23:38:21:** 4 failed attempts
* **23:45:34 – 23:45:39:** 4 failed attempts
* **23:52:34 – 23:52:35:** 2 failed attempts

The repeated failures originated from `127.0.0.1`, indicating localhost activity rather than a remote source.

---

## 4. Authentication Correlation

The failed authentication activity was correlated with successful Windows authentication events.

One observed sequence was:

```text
20:29:23.355  4625  Failed
20:29:26.495  4625  Failed
20:29:27.792  4625  Failed
20:29:29.840  4625  Failed
              ↓
20:29:39.546  4624  Successful
```

The successful authentication was associated with:

* **Account:** `sumedhmore013@outlook.com`
* **Source IP:** `127.0.0.1`
* **Logon Type:** 11 — Cached Interactive

A subsequent Event ID 4624 with Logon Type 7 was also observed, representing a workstation unlock event.

The correlation query identified a maximum of **8 failed attempts** associated with a subsequent successful authentication during the lab activity.

---

## 5. Analysis

The repeated Event ID 4625 events match a behavioral pattern that can be associated with password guessing.

However, the available evidence does not establish a real attack or account compromise.

Several factors indicate that the activity was benign in this lab:

1. The source IP was `127.0.0.1` (localhost).
2. The failed attempts were generated intentionally for detection testing.
3. The authentication activity occurred on the controlled Windows lab machine.
4. The successful authentication occurred after the intentionally generated failed attempts.

Therefore, the events should be classified as **Benign / Lab Simulation** rather than a confirmed brute-force attack.

---

## 6. MITRE ATT&CK Mapping

**Tactic:** Credential Access

**Technique:** T1110 — Brute Force

**Sub-technique:** T1110.001 — Password Guessing

The detection logic is aligned with T1110.001 because it identifies repeated authentication failures that can indicate password-guessing behavior.

The mapping represents the behavior the detection is designed to identify and does not indicate that an actual adversary was present in this lab.

---

## 7. Recommended SOC Response

If the same detection occurred in a real environment, an analyst should:

1. Identify the source IP and determine whether it is internal or external.
2. Identify the targeted account.
3. Examine the number and frequency of failed authentication attempts.
4. Correlate Event ID 4625 with Event ID 4624.
5. Investigate the successful authentication for unusual source, time, location, or logon type.
6. Review additional authentication and endpoint events around the alert.
7. Determine whether the activity is legitimate, suspicious, or malicious.
8. Escalate or contain the account/session if additional evidence indicates compromise.

---

## 8. Investigation Conclusion

The Splunk detection successfully identified repeated Windows authentication failures and correlated them with subsequent successful authentication.

The lab generated multiple failed-logon bursts, including a sequence of four failed interactive logons followed by a successful authentication.

The detection and correlation logic functioned as expected.

**Final Classification: Benign / Lab Simulation**

**Detection Status: Successful**
