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

failed_login_attempts AS (
  -- Step 1: Isolate failed logins in the last 7 days and use a window function 
  -- to find the timestamp of the 5th prior failed attempt for the same IP.
  SELECT 
    CLIENT_IP,
    USER_NAME,
    EVENT_TIMESTAMP,
    LAG(EVENT_TIMESTAMP, 5) OVER (
      PARTITION BY CLIENT_IP 
      ORDER BY EVENT_TIMESTAMP
    ) AS fifth_prev_timestamp
  FROM 
    SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
  WHERE 
    EVENT_TIMESTAMP >= DATEADD(day, -7, CURRENT_TIMESTAMP())
    AND IS_SUCCESS = 'NO'
),

brute_force_bursts AS (
  -- Step 2: Filter for instances where the 6th failure (current row) 
  -- happened within 30 seconds of the 1st failure (5 rows ago).
  SELECT 
    CLIENT_IP,
    fifth_prev_timestamp AS burst_start_time,
    EVENT_TIMESTAMP AS burst_end_time
  FROM 
    failed_login_attempts
  WHERE 
    fifth_prev_timestamp IS NOT NULL
    AND DATEDIFF(second, fifth_prev_timestamp, EVENT_TIMESTAMP) <= 30
),

brute_force as (
  SELECT 
    CLIENT_IP,
    COUNT(*) AS brute_force_triggers,
    MIN(burst_start_time) AS first_burst_detected,
    MAX(burst_end_time) AS latest_burst_detected
  FROM 
    brute_force_bursts
  GROUP BY 
    CLIENT_IP
  HAVING
    brute_force_triggers > 5
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
| Brute force failure threshold | 5+ failures | Login events from an IP are considered as a single Brute Force attempt if the number of failures within the Brute force time window exceed the threshold |
| Brute force time window | 30 seconds | Time window to determine whether a login failure was a brute force attempt|
| Brute force trigger threshold | 5+ triggers | IP considered as a Brute Force IP if at least the specified number of failures are observed in the Brute force time window |

## Output

- Table of anomalous login events with risk scores
- Summary by risk level
- Recommendations for high-risk findings
