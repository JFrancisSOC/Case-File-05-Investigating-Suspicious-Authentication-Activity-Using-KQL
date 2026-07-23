# Case File 05 – Investigating Suspicious Authentication Activity Using Kusto Query Language (KQL)

## Overview

This investigation analyzes authentication activity using **Azure Data Explorer** and **Kusto Query Language (KQL)** to identify suspicious login behavior within an enterprise environment.

The objective was to detect abnormal authentication patterns, identify high-risk source IP addresses, correlate usernames with authentication attempts, and determine whether any accounts showed indicators of compromise.

---

## Objectives

- Analyze authentication logs using KQL
- Compare successful and failed login attempts
- Identify accounts experiencing repeated failed logins
- Detect suspicious public source IP addresses
- Correlate usernames with source IPs
- Analyze authentication timelines
- Investigate login activity during unusual hours
- Determine whether suspicious activity resulted in successful authentication
- Document findings and recommendations

---

## Environment

| Component | Value |
|------------|--------|
| Platform | Azure Data Explorer |
| Database | SecurityLogs |
| Table | AuthenticationEvents |
| Query Language | Kusto Query Language (KQL) |

---

## Skills Demonstrated

- Azure Data Explorer
- Kusto Query Language (KQL)
- Authentication Log Analysis
- Threat Hunting
- Password Spray Investigation
- Source IP Correlation
- Timeline Analysis
- Login Behavior Analysis
- IOC Identification
- Security Event Investigation
- Security Documentation
- SOC Analyst Methodology

---

# Investigation Process

## Step 1 – Review Authentication Events

The investigation began by reviewing the **AuthenticationEvents** table to understand the available log fields and establish a baseline of authentication activity.

![Azure Data Explorer SecurityLogs Tables](01%20Azure%20Data%20Explorer%20SecurityLogs%20Tables.png)

---

## Step 2 – Retrieve Authentication Events

A KQL query was executed to retrieve authentication events, including timestamps, usernames, source IP addresses, hostnames, and authentication results.

![First KQL Authentication Query](02%20First%20KQL%20Authentication%20Query.png)

---

## Step 3 – Compare Successful vs. Failed Logins

Authentication events were summarized to compare successful and failed login attempts across the environment.

### Findings

- Failed Logins: **2,177**
- Successful Logins: **1,692**

![Authentication Results Summary](03%20Authentication%20Results%20Summary.png)

---

## Step 4 – Identify Accounts with Repeated Failed Logins

Authentication failures were grouped by username to identify accounts experiencing the highest number of failed login attempts.

![Top Accounts by Failed Login Attempts](04%20Top%20Accounts%20by%20Failed%20Login%20Attempts.png)

---

## Step 5 – Identify Suspicious Source IP Addresses

Authentication events were grouped by source IP address. One public IP immediately stood out:

**88.150.11.111**

![Top Source IPs by Failed Login Attempts](05%20Top%20Source%20IPs%20by%20Failed%20Login%20Attempts.png)

---

## Step 6 – Correlate Usernames with Source IP Addresses

Authentication events were correlated by username and source IP to determine whether multiple accounts were targeted from the same location.

![Source IP and Username Correlation](06%20Source%20IP%20and%20Username%20Correlation.png)

---

## Step 7 – Investigate Public IP Activity

The investigation pivoted to analyze all authentication activity originating from **88.150.11.111**.

The IP generated both successful and failed authentication attempts across multiple user accounts.

![Public IP Account Probing](07%20Public%20IP%20Account%20Probing.png)

---

## Step 8 – Compare Successful and Failed Logins from the Public IP

Authentication events from the investigated IP were summarized by authentication result.

### Findings

- Successful Logins: **11**
- Failed Logins: **10**

![Successful and Failed Logins from Public IP](08%20Successful%20and%20Failed%20Logins%20from%20Public%20IP.png)

---

## Step 9 – Review Successful Accounts from the Public IP

Successful authentication events were filtered to identify the user accounts that successfully authenticated from the investigated public IP.

![Successful Accounts from Public IP](09%20Successful%20Accounts%20from%20Public%20IP.png)

---

## Step 10 – Review the Authentication Timeline

Authentication events were sorted chronologically to determine whether failed login attempts were followed by successful authentication.

![Public IP Authentication Timeline](10%20Public%20IP%20Authentication%20Timeline.png)

---

## Step 11 – Compare Successful User Source IPs

Successfully authenticated users were analyzed to determine whether they also authenticated from additional source IP addresses.

This helped distinguish legitimate user activity from potentially suspicious authentication events.

![Successful Account Source IP Comparison](11%20Successful%20Account%20Source%20IP%20Comparison.png)

---

## Step 12 – Investigate High-Risk User Authentication Timeline

Authentication events for selected accounts were reviewed chronologically to determine whether successful logins followed previous failed authentication attempts.

![High-Risk Account Authentication Timeline](12%20High-Risk%20Account%20Authentication%20Timeline.png)

---

## Step 13 – Analyze Login Hours

Successful authentication events were grouped by hour to identify activity occurring outside normal business hours.

![High-Risk Account Login Hours](13%20High-Risk%20Account%20Login%20Hours.png)

---

## Step 14 – Review MAIL-SERVER01 Login Activity

Successful authentication events on **MAIL-SERVER01** were grouped by hour to identify peak login periods.

![MAIL-SERVER01 Successful Logins by Hour](14%20MAIL-SERVER01%20Successful%20Logins%20by%20Hour.png)

---

## Step 15 – Identify Successful Logins During Unusual Hours

Authentication events occurring during unusual hours were isolated for additional review.

![Only Successful Logins at Unusual Hours](15%20Only%20Successful%20Logins%20at%20Unusual%20Hours.png)

---

## Step 16 – Confirm Activity on MAIL-SERVER01

Authentication activity from the investigated public IP was confirmed to be isolated to **MAIL-SERVER01**.

![Public IP Activity Limited to MAIL-SERVER01](16%20Public%20IP%20Activity%20Limited%20to%20MAIL-SERVER01.png)

---

## Step 17 – Compare Source IP Activity

The investigated source IP was summarized to determine total authentication events, successful logins, failed logins, and unique usernames involved.

![Source IP Comparison on MAIL-SERVER01](17%20Source%20IP%20Comparison%20on%20MAIL-SERVER01.png)

---

# Indicators of Compromise (IOCs)

| Indicator | Value |
|-----------|-------|
| Suspicious Public IP | 88.150.11.111 |
| Secondary Public IP | 149.124.195.189 |
| Target Host | MAIL-SERVER01 |
| Total Events | 21 |
| Successful Logins | 11 |
| Failed Logins | 10 |
| Unique Usernames | 21 |

---

# Findings

- Failed authentication attempts exceeded successful logins across the environment.
- Public IP **88.150.11.111** generated repeated failed and successful authentication attempts.
- Authentication activity was isolated to **MAIL-SERVER01**.
- Several users authenticated from additional source IP addresses, suggesting legitimate user activity outside the investigated IP.
- Successful logins occurred after previous failed authentication attempts.
- Successful authentication events were observed during unusual login hours.

---

# MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Password Spraying | T1110.003 |
| Valid Accounts | T1078 |
| External Remote Services | T1133 |

---

# Recommendations

- Investigate the public IP using threat intelligence.
- Review Azure AD sign-in logs.
- Verify Multi-Factor Authentication (MFA) enforcement.
- Review Conditional Access policies.
- Investigate endpoint telemetry using Microsoft Defender.
- Review impossible travel and geolocation events.
- Continue monitoring authentication activity associated with the identified IP.

---

# Conclusion

This investigation identified a public IP address responsible for repeated failed authentication attempts followed by multiple successful logins against **MAIL-SERVER01**. Although the available log data did not conclusively confirm account compromise, the observed authentication pattern is consistent with password spraying or credential-based attacks and warrants additional investigation.

Further analysis using Azure AD logs, Microsoft Defender telemetry, MFA events, Conditional Access policies, and threat intelligence would help determine whether the observed activity represents malicious behavior or legitimate remote access.

**Final Assessment:** Suspicious Authentication Activity

**Severity:** Medium
