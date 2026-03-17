---
name: audit-monitoring
description: "Audit logging and SIEM integration. Covers security event export, critical alerts, and anomaly detection."
---

# Audit & Monitoring Sub-Skill

> **Compliance**: NIST AU-2, AU-3, AU-6, AU-12 | CIS 8.2, 8.5, 8.11 | SOC 2 CC7.2, CC7.3 | ISO A.12.4 | PCI-DSS 10.1, 10.2, 10.3 | HIPAA 164.312(b)

## Assessment Queries

### Login Failure Rate

```sql
SELECT 
  COUNT(*) as total_attempts,
  SUM(CASE WHEN is_success = 'YES' THEN 1 ELSE 0 END) as successful,
  SUM(CASE WHEN is_success = 'NO' THEN 1 ELSE 0 END) as failed,
  ROUND(100.0 * SUM(CASE WHEN is_success = 'NO' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) as failure_rate
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE event_timestamp > DATEADD(day, -7, CURRENT_TIMESTAMP());
```

**Best Practice**: <5% login failure rate

### ACCOUNTADMIN Login from Unknown IP

```sql
SELECT 
  user_name,
  client_ip,
  first_authentication_factor,
  event_timestamp
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE reported_client_type IS NOT NULL
  AND user_name IN (
    SELECT DISTINCT grantee_name 
    FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS 
    WHERE role = 'ACCOUNTADMIN'
  )
  AND event_timestamp > DATEADD(hour, -24, CURRENT_TIMESTAMP())
ORDER BY event_timestamp DESC;
```

### Privilege Escalation Detection

```sql
SELECT 
  query_text,
  user_name,
  role_name,
  start_time
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_text ILIKE '%GRANT%ACCOUNTADMIN%'
   OR query_text ILIKE '%GRANT%SECURITYADMIN%'
  AND start_time > DATEADD(hour, -24, CURRENT_TIMESTAMP());
```

### Mass Data Access Detection

```sql
SELECT 
  user_name,
  role_name,
  SUM(rows_produced) as total_rows,
  SUM(bytes_scanned) as total_bytes
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE start_time > DATEADD(hour, -1, CURRENT_TIMESTAMP())
GROUP BY user_name, role_name
HAVING total_bytes > 10000000000;
```

## Remediation SQL

### Create Security Event Export Task

```sql
CREATE TABLE IF NOT EXISTS security_export_tracking (
  view_name VARCHAR PRIMARY KEY,
  last_exported_timestamp TIMESTAMP_LTZ DEFAULT '1970-01-01'::TIMESTAMP_LTZ
);

CREATE TASK export_security_events
  WAREHOUSE = SECURITY_WH
  SCHEDULE = '5 MINUTE'
AS
BEGIN
  LET last_ts TIMESTAMP_LTZ := (SELECT COALESCE(last_exported_timestamp, '1970-01-01'::TIMESTAMP_LTZ) 
                                FROM security_export_tracking WHERE view_name = 'LOGIN_HISTORY');
  
  COPY INTO @security_export_stage/login_events/
  FROM (
    SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
    WHERE event_timestamp > :last_ts
  )
  FILE_FORMAT = (TYPE = JSON);
  
  MERGE INTO security_export_tracking t USING (SELECT 'LOGIN_HISTORY' as view_name, CURRENT_TIMESTAMP() as ts) s
    ON t.view_name = s.view_name
    WHEN MATCHED THEN UPDATE SET last_exported_timestamp = s.ts
    WHEN NOT MATCHED THEN INSERT (view_name, last_exported_timestamp) VALUES (s.view_name, s.ts);
END;

ALTER TASK export_security_events RESUME;
```

## SIEM Integration Reference

| SIEM Platform | Integration Method | Key Data Sources |
|--------------|-------------------|-----------------|
| Splunk | Snowflake Connector for Splunk, or Kafka | LOGIN_HISTORY, QUERY_HISTORY, GRANTS_TO_* |
| Microsoft Sentinel | Azure Event Hub + Data Connector | Access events, configuration changes |
| Elastic SIEM | Logstash with JDBC input | All ACCOUNT_USAGE views |
| Chronicle | BigQuery export + Chronicle ingestion | Full audit trail |

## Checklist

- [ ] SIEM integration configured for security events
- [ ] Critical alerts defined (ACCOUNTADMIN login, privilege escalation, data exfil)
- [ ] Audit log retention meets compliance requirements
- [ ] Regular access reviews scheduled (quarterly minimum)
