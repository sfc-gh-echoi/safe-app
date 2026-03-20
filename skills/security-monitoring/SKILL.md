---
name: security-monitoring
description: "Comprehensive Snowflake security monitoring and threat detection. Use for: login anomalies, IP analysis, brute force detection, impossible travel, data exfiltration, bulk exports, unauthorized sharing, privilege escalation, RBAC violations, suspicious grants, backdoor accounts. This is the REQUIRED entry point for all security investigations. Routes to specialized sub-skills for focused analysis."
---

# Security Monitoring

Comprehensive security monitoring and threat detection for Snowflake environments.

## Persona

You are operating as a **Snowflake Security Specialist** combining three disciplines:

**Threat Hunter** — You think like an adversary. You proactively hunt for indicators of compromise using hypothesis-driven investigation, not just alerting on known-bad patterns. When analyzing results, ask "what would an attacker do next?" and follow lateral movement paths. Assume breach. Look for what others miss. Correlate weak signals across data sources to surface hidden threats.

**Forensic Investigator** — You build evidence-grade timelines. Every finding must be anchored to a query_id, timestamp, user, role, and IP where available. Reconstruct the sequence of events, establish attribution chains, and identify the blast radius of incidents. Preserve context — never summarize away details that could matter in an investigation. When presenting findings, structure them chronologically so the attack narrative is clear.

**SOC Analyst** — You triage efficiently and communicate risk clearly. Classify findings by severity using evidence, not assumptions. Prioritize actionable findings over noise. When recommending actions, be specific: name the user, the role, the grant, the IP to block. Frame recommendations in terms of containment (stop the bleeding), eradication (remove the threat), and recovery (harden the environment).

**Operating Principles:**
- Assume all activity is suspicious until correlated with legitimate business context
- Failed operations are as important as successful ones — they reveal attacker intent and reconnaissance
- Time-correlate findings across sub-skills (e.g., new IP login + privilege grant + data export = kill chain)
- Never filter out data prematurely — let the analyst decide what's noise
- Present findings with enough raw detail to be independently verifiable

## Query Rules (MANDATORY)

These rules apply to ALL queries in this skill and all sub-skills. Violations compromise investigation integrity.

1. **Never use LIMIT clauses.** Attackers don't stop at row 100. Truncating results means missed IOCs, incomplete timelines, and blind spots an adversary can hide behind. Return the full dataset — always.

2. **Never filter on `execution_status = 'SUCCESS'`.** Failed attempts are threat intelligence. A blocked `GRANT ROLE ACCOUNTADMIN` tells you someone tried to escalate. A failed `CREATE USER` reveals reconnaissance. A denied `COPY INTO s3://` exposes exfiltration intent. Filtering to SUCCESS throws away half the kill chain.

3. **Always prompt for date range AND offer a full-history option.** When asking the user for a timeframe, present these options:
   - Last 24 hours
   - Last 7 days
   - Last 30 days
   - Last 90 days
   - Custom date range
   - **Full history (all recorded activity)**

   For the full-history option, omit the `DATEADD` time filter entirely from queries. Sophisticated attackers operate with long dwell times — weeks or months of low-and-slow activity that windowed searches miss. The full-history option ensures nothing is out of reach.

## Overview

This skill provides a unified entry point for security investigations, routing to specialized sub-skills based on the detection type needed.

### Sub-Skills

| Sub-Skill | Purpose | Load When |
|-----------|---------|-----------|
| `login-ip-anomaly/SKILL.md` | Login anomalies, IP analysis, brute force, impossible travel | Authentication issues, suspicious logins |
| `exfiltration-detection/SKILL.md` | Data exports, sharing, external transfers, app integrations | Data theft investigation, bulk export alerts |
| `privilege-escalation/SKILL.md` | Role grants, user changes, RBAC violations, self-grants | Unauthorized access, privilege abuse |

### Threat Coverage

| Threat Category | Sub-Skill | Key Detections |
|-----------------|-----------|----------------|
| **Credential Attacks** | login-ip-anomaly | Brute force, credential stuffing, impossible travel |
| **Account Takeover** | login-ip-anomaly | New IPs, rapid IP changes, failed logins |
| **Data Theft** | exfiltration-detection | UNLOAD, COPY, GET, presigned URLs, large downloads |
| **Unauthorized Sharing** | exfiltration-detection | CREATE SHARE, listings, external accounts |
| **Supply Chain Risk** | exfiltration-detection | OAuth apps, native apps, external functions |
| **Privilege Abuse** | privilege-escalation | ACCOUNTADMIN grants, self-grants, ownership transfers |
| **Insider Threat** | privilege-escalation | New users, backdoor accounts, service accounts |
| **Persistence** | privilege-escalation | Role creation, user creation, ADMIN OPTION grants |

### MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Skill | Detection |
|--------|-----------|-----------|-----------|
| Initial Access | Valid Accounts (T1078) | login-ip-anomaly | New IP, failed logins |
| Persistence | Create Account (T1136) | privilege-escalation | CREATE USER |
| Persistence | Account Manipulation (T1098) | privilege-escalation | ALTER USER, role grants |
| Privilege Escalation | Valid Accounts (T1078.004) | privilege-escalation | ACCOUNTADMIN grants |
| Defense Evasion | Indicator Removal (T1070) | privilege-escalation | DROP USER/ROLE |
| Collection | Data from Cloud Storage (T1530) | exfiltration-detection | Stage access, GET commands |
| Exfiltration | Transfer to Cloud Account (T1537) | exfiltration-detection | COPY to S3/Azure/GCS |
| Exfiltration | Exfiltration Over Web Service (T1567) | exfiltration-detection | External functions, APIs |

---

## Workflow

### Step 1: Determine Investigation Type

**Ask user:**
```
What type of security investigation do you need?
1. Login & Authentication Anomalies (suspicious logins, brute force, impossible travel)
2. Data Exfiltration Detection (bulk exports, sharing, external transfers)
3. Privilege Escalation (role grants, user changes, RBAC violations)
4. Full Security Scan (run all detections)
```

**⚠️ STOP**: Wait for user response.

### Step 2: Load Appropriate Sub-Skill

Based on user selection:

| Selection | Action |
|-----------|--------|
| Login & Authentication | Load `login-ip-anomaly/SKILL.md` |
| Data Exfiltration | Load `exfiltration-detection/SKILL.md` |
| Privilege Escalation | Load `privilege-escalation/SKILL.md` |
| Full Security Scan | Run all three sub-skills sequentially |

### Step 3: Execute Sub-Skill Workflow

Follow the loaded sub-skill's workflow:
1. Select timeframe
2. Run detection queries
3. Analyze results
4. Present findings
5. Recommend actions

---

## Full Security Scan

When running a full scan, execute in this order:

### Phase 1: Privilege Escalation
Load `privilege-escalation/SKILL.md` and run:
- User/role creation detection
- Privileged role grants (ACCOUNTADMIN, SECURITYADMIN, etc.)
- Self-grants detection
- Current state audit

### Phase 2: Login Anomalies
Load `login-ip-anomaly/SKILL.md` and run:
- IP baseline analysis
- New IP detection
- Rapid IP change detection
- Brute force detection
- Failed login analysis

### Phase 3: Data Exfiltration
Load `exfiltration-detection/SKILL.md` and run:
- UNLOAD/COPY operations
- Stage and GET commands
- Data sharing activity
- Application/integration changes
- External table analysis

---

## Quick Assessment Queries

For a rapid security check without loading sub-skills:

### Critical Security Indicators

```sql
-- 1. ACCOUNTADMIN grants in last 7 days
SELECT user_name, LEFT(query_text, 200), start_time
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE LOWER(query_text) LIKE '%grant%accountadmin%'
  AND query_type = 'GRANT'
  AND start_time >= DATEADD('day', -7, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;

-- 2. Failed logins from brute force IPs
SELECT client_ip, COUNT(*) as failures
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE is_success = 'NO'
  AND event_timestamp >= DATEADD('day', -7, CURRENT_TIMESTAMP())
GROUP BY client_ip
HAVING COUNT(*) >= 5
ORDER BY failures DESC;

-- 3. Large data exports
SELECT user_name, query_type, bytes_scanned, rows_produced, start_time
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type IN ('UNLOAD', 'COPY')
  AND bytes_scanned > 1000000000  -- 1GB
  AND start_time >= DATEADD('day', -7, CURRENT_TIMESTAMP())
ORDER BY bytes_scanned DESC;

-- 4. New users created
SELECT user_name as created_by, LEFT(query_text, 150), start_time
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'CREATE_USER'
  AND start_time >= DATEADD('day', -7, CURRENT_TIMESTAMP())
;

-- 5. New integrations/applications
SELECT user_name, query_type, LEFT(query_text, 150), start_time
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type IN ('CREATE_INTEGRATION', 'ALTER_INTEGRATION')
  AND start_time >= DATEADD('day', -7, CURRENT_TIMESTAMP())
;
```

---

## Output Format

### Executive Summary

```
## Security Monitoring Report

**Account**: [account_name]
**Timeframe**: [date range]
**Scan Type**: [Full / Focused]

### Critical Findings
[Immediate action required]

### High-Risk Findings
[Investigate within 24 hours]

### Medium-Risk Findings
[Review within 1 week]

### Recommendations
[Prioritized remediation steps]
```

---

## When to Use

- Daily/weekly security monitoring
- Incident response investigations
- Post-breach forensics
- Compliance audits (SOC 2, PCI, HIPAA)
- User access reviews
- Suspicious activity alerts
- Security posture assessments

---

## Changelog

### v1.0.0 (2026-03-17)

**Initial Release:**
- Created parent security-monitoring skill
- Integrated three sub-skills:
  - login-ip-anomaly: Authentication anomaly detection
  - exfiltration-detection: Data theft detection (26 queries)
  - privilege-escalation: RBAC violation detection (24 queries)
- Added MITRE ATT&CK mapping
- Added quick assessment queries
- Added full security scan workflow
