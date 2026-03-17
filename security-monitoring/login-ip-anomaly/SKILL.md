---
name: login-ip-anomaly
description: "Detect IP address anomalies in Snowflake LOGIN_HISTORY. Use when: login anomalies, suspicious IPs, brute force detection, impossible travel, IP sharing, failed login analysis, security audit of logins."
---

# Login IP Anomaly Detection

## When to Use
- Detect suspicious login patterns
- Find brute force attempts
- Identify impossible travel (rapid IP changes)
- Audit failed logins
- Find shared IPs across users

## Workflow

### Step 1: Confirm Connection
**Ask** user which Snowflake connection to use if not specified.

Requires `IMPORTED PRIVILEGES` on SNOWFLAKE database for ACCOUNT_USAGE access.

### Step 2: Run Anomaly Detection

Execute the following query (adjust thresholds as needed):

```sql
WITH user_ip_baseline AS (
  SELECT 
    user_name, client_ip,
    COUNT(*) AS login_count,
    MIN(event_timestamp) AS first_seen,
    MAX(event_timestamp) AS last_seen
  FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
  WHERE event_timestamp >= DATEADD('day', -30, CURRENT_TIMESTAMP())
    AND client_ip != '0.0.0.0'
  GROUP BY user_name, client_ip
),

recent_logins AS (
  SELECT 
    event_timestamp, user_name, client_ip, reported_client_type,
    is_success, error_message,
    LAG(event_timestamp) OVER (PARTITION BY user_name ORDER BY event_timestamp) AS prev_login_time,
    LAG(client_ip) OVER (PARTITION BY user_name ORDER BY event_timestamp) AS prev_ip
  FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
  WHERE event_timestamp >= DATEADD('day', -7, CURRENT_TIMESTAMP())
    AND client_ip != '0.0.0.0'
),

anomalies AS (
  SELECT r.*,
    CASE WHEN b.client_ip IS NULL THEN TRUE ELSE FALSE END AS is_new_ip,
    CASE WHEN r.prev_ip IS NOT NULL AND r.prev_ip != r.client_ip 
         AND DATEDIFF('minute', r.prev_login_time, r.event_timestamp) < 10 
         THEN TRUE ELSE FALSE END AS is_rapid_ip_change,
    CASE WHEN r.is_success = 'NO' THEN TRUE ELSE FALSE END AS is_failed_login,
    b.login_count AS historical_login_count
  FROM recent_logins r
  LEFT JOIN user_ip_baseline b ON r.user_name = b.user_name AND r.client_ip = b.client_ip
),

ip_sharing AS (
  SELECT client_ip, COUNT(DISTINCT user_name) AS user_count
  FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
  WHERE event_timestamp >= DATEADD('day', -7, CURRENT_TIMESTAMP())
    AND client_ip != '0.0.0.0'
  GROUP BY client_ip HAVING COUNT(DISTINCT user_name) > 3
),

brute_force AS (
  SELECT client_ip, COUNT(*) AS failed_attempts
  FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
  WHERE event_timestamp >= DATEADD('day', -7, CURRENT_TIMESTAMP()) 
    AND is_success = 'NO'
    AND client_ip != '0.0.0.0'
  GROUP BY client_ip HAVING COUNT(*) >= 5
)

SELECT 
  a.event_timestamp, a.user_name, a.client_ip, a.is_success, a.error_message,
  a.is_new_ip, a.is_rapid_ip_change, a.is_failed_login,
  s.client_ip IS NOT NULL AS is_shared_ip,
  bf.client_ip IS NOT NULL AS is_brute_force_ip,
  (IFF(a.is_new_ip, 2, 0) + IFF(a.is_rapid_ip_change, 3, 0) + IFF(a.is_failed_login, 1, 0) +
   IFF(s.client_ip IS NOT NULL, 2, 0) + IFF(bf.client_ip IS NOT NULL, 4, 0)) AS risk_score
FROM anomalies a
LEFT JOIN ip_sharing s ON a.client_ip = s.client_ip
LEFT JOIN brute_force bf ON a.client_ip = bf.client_ip
WHERE a.is_new_ip OR a.is_rapid_ip_change OR a.is_failed_login 
   OR s.client_ip IS NOT NULL OR bf.client_ip IS NOT NULL
ORDER BY risk_score DESC, event_timestamp DESC
LIMIT 100;
```

### Step 3: Summarize Findings

Present results grouped by:

| Risk Score | Anomaly Type |
|------------|--------------|
| **8+** | Critical - Multiple flags (investigate immediately) |
| **5-7** | High - Brute force or rapid IP change with failures |
| **3-4** | Medium - New IP or shared IP |
| **1-2** | Low - Failed login only |

## Configurable Thresholds

| Parameter | Default | Description |
|-----------|---------|-------------|
| Baseline window | 30 days | History for known IPs |
| Detection window | 7 days | Recent activity to scan |
| Rapid IP change | 10 min | Max time between different IPs |
| Shared IP threshold | 3+ users | IPs flagged as shared |
| Brute force threshold | 5+ failures | Failed attempts to flag IP |

## Output

- Table of anomalous login events with risk scores
- Summary by risk level
- Recommendations for high-risk findings
