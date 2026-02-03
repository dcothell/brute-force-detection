# 🛡️ Virtual Machine Brute Force Detection & Incident Response  
**Platform:** Microsoft Sentinel  
**Log Source:** Microsoft Defender for Endpoint  
**Technique:** Brute Force Authentication (MITRE ATT&CK T1110)

---

## 📌 Scenario Overview

This scenario demonstrates the detection, investigation, and response to a brute force authentication attempt targeting Azure virtual machines. A Microsoft Sentinel analytics rule was created to identify repeated failed logon attempts originating from the same external IP address against the same host within a defined time window.

The incident was investigated following the NIST Incident Response Lifecycle and closed after confirming no successful authentication or system compromise.

---

## 🧰 Environment & Tools

- **Azure Virtual Machines** – Target systems
- **Microsoft Defender for Endpoint (MDE)** – Endpoint telemetry source
- **Microsoft Sentinel (SIEM)** – Detection, alerting, and incident management
- **Log Analytics Workspace** – Centralized log storage
- **KQL (Kusto Query Language)** – Log analysis
- **MITRE ATT&CK Framework** – Attack classification

---

## 🧠 Incident Response Framework

This scenario follows the **NIST Incident Response Lifecycle**:

1. Preparation  
2. Detection & Analysis  
3. Containment  
4. Eradication  
5. Recovery  
6. Post-Incident Activities  
7. Closure  

---

## 🚨 Detection Phase

### Analytics Rule Configuration

**Rule Name:**  
`unr3st – Brute Force Attempt Detection`

**Description:**  
Detects brute force authentication attempts where the same IP address fails to log into the same virtual machine multiple times within a short period.

### Detection Logic (KQL)

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where TimeGenerated > ago(5h)
| summarize FailedAttempts = count() by RemoteIP, DeviceName
| where FailedAttempts >= 10
| order by FailedAttempts desc
````

### Rule Settings

* **Query Frequency:** Every 4 hours
* **Lookback Period:** 5 hours
* **Alert Threshold:** Results > 0
* **Incident Creation:** Enabled
* **Event Grouping:** Single incident per 24 hours
* **Suppression:** 24 hours
* **MITRE ATT&CK Mapping:**

  * T1110 – Brute Force
  * T1110.001 – Password Guessing

---

## 🕵️ Detection & Analysis Phase

### Incident Trigger

The analytics rule successfully triggered, creating a Microsoft Sentinel incident.

### Investigation

* The Sentinel investigation graph identified:

  * Multiple external IP addresses
  * Multiple Azure virtual machines as targets
* Entity mapping confirmed attacker-to-host relationships consistent with brute force activity.

### Log Validation (Successful Authentication Check)

Focused analysis was performed to verify whether any brute force attempts resulted in successful authentication.

```kql
DeviceLogonEvents
| where DeviceName == "cyberlab"
| where RemoteIP == "110.227.205.232"
| where ActionType == "LogonSuccess"
| order by TimeGenerated desc
```

**Result:**
No successful authentication events were observed.

---

## 🧯 Containment (Real-World Example)

> *Containment actions were documented as examples and not executed to avoid disrupting shared lab infrastructure.*

If this were a production environment:

* Affected endpoints would be isolated using Microsoft Defender for Endpoint.
* Network Security Group (NSG) rules would be restricted to trusted IP addresses only.
* Attacker IPs would be blocked at the perimeter.

---

## 🧹 Eradication & Recovery (Real-World Example)

If compromise had occurred:

* Affected credentials would be reset.
* Antivirus and endpoint scans would be executed.
* Systems would be restored with hardened access controls such as MFA or Just-In-Time access.
* Post-recovery monitoring would be enabled.

---

## 🧠 Post-Incident Activities

### Documentation

* All findings were documented in the Sentinel incident activity log.
* Investigation steps, queries, and conclusions were recorded.

### Lessons Learned

* Publicly exposed management services are frequent brute force targets.
* SIEM-based detection is effective even when attacks are unsuccessful.
* Entity mapping significantly improves investigation efficiency.
* Successful authentication validation is critical before declaring impact.

### Recommendations

* Restrict management ports from public exposure.
* Use Azure Bastion, MFA, or JIT access for administrative access.
* Maintain continuous monitoring and alerting.

---

## ✅ Incident Closure

* **Classification:** True Positive
* **Impact:** None
* **Compromise:** No

**Closure Statement:**
Brute force authentication attempts were confirmed against Azure virtual machines. Log analysis verified no successful authentication or system compromise. The incident was documented and closed following standard SOC procedures.

---

## 🧹 Cleanup

* The incident was deleted after validation.
* The custom analytics rule was removed to clean up the lab environment.
* No persistent changes were made to shared infrastructure.

---

## 🎯 Key Takeaways

* Demonstrated end-to-end SOC workflow using Microsoft Sentinel
* Built and validated a custom brute force detection rule
* Investigated an incident using entity mapping and log analysis
* Applied NIST incident response methodology
* Performed proper documentation, closure, and cleanup

---

🛡️ *This scenario reflects real-world SOC incident response practices using Microsoft Sentinel.*

Just say the word 👊
```
