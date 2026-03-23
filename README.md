# splunk-bruteforce-detection
first splunk project (brute-force detecion)
#  Brute Force Detection with Splunk

## Project Overview
This project demonstrates how to detect SSH brute force attacks 
using Splunk Enterprise and Linux authentication logs (authlog).
It covers threshold detection, attacker identification, and 
compromised account correlation.

## Data Source
Custom Linux SSH log file (authlog) containing real attack 
patterns including failed logins and a successful breach.

## Attack Scenarios Detected

### 1. Failed Login Attempts Over Time
Visualizes failed SSH logins per attacker IP using a timechart.

**Query:**
index=_* OR index=* sourcetype=authlog "Failed Password" 
| timechart count by src_ip
```
**Finds:** Attack timing and which IPs are most active.


### 2. Threshold-Based Brute Force Detection
Flags IPs with more than 3 failed attempts within 1 minute.

Taha Yassine Achour

**Query:**
```
index=_* OR index=* sourcetype=authlog "Failed Password" 
| bin _time span=1m
| stats count by src_ip, _time
| where count > 3
```
**Finds:** `172.16.0.3` (6 attempts) and `192.168.1.10` (5 attempts)

---

### 3. Targeted Username Identification
Extracts which usernames were targeted by each attacker.

**Query:**
```
index=* sourcetype=authlog
| rex field=_raw "for (invalid user )?(?<username>\w+) 
  from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip, username
| sort - count
```
**Finds:** `172.16.0.3` targeted `root`, `192.168.1.10` targeted `admin`

---

### 4. Compromised Account Detection 
Correlates failed logins with a successful login from the same IP.

**Query:**
```
index=* sourcetype=authlog
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval status=if(searchmatch("Failed password"), "failed", "success")
| stats count(eval(status="failed")) as failed_count,
        count(eval(status="success")) as success_count by src_ip
| where failed_count > 3 AND success_count > 0
| eval alert="Brute Force SUCCESS - Account Compromised"
