---
name: notifications
description: "Security change notifications and alerting. Covers email notifications, webhooks, Slack/Teams integration, and real-time privilege escalation detection."
---

# Security Notifications Sub-Skill

> **Compliance**: NIST AU-5, IR-6, SI-4 | CIS 8.11, 17.4, 17.9 | SOC 2 CC7.3, CC7.4 | ISO A.12.4, A.16.1 | PCI-DSS 10.7, 12.10 | HIPAA 164.308(a)(6)

## Alert Types Reference

| Alert Type | Severity | Description |
|------------|----------|-------------|
| ACCOUNTADMIN_GRANT | CRITICAL | New ACCOUNTADMIN role grant detected |
| ACCOUNT_NETWORK_POLICY_REMOVED | CRITICAL | Account-level network policy removed |
| PASSWORD_POLICY_REMOVED | CRITICAL | Account password policy removed or weakened |
| CORTEX_USER_PUBLIC_GRANT | CRITICAL | CORTEX_USER granted to PUBLIC role |
| SECURITYADMIN_GRANT | HIGH | New SECURITYADMIN role grant detected |
| MFA_DISABLED_ADMIN | CRITICAL | MFA disabled for privileged user |
| DORMANT_USER_THRESHOLD | MEDIUM | Dormant user count exceeds threshold |
| FAILED_LOGIN_SPIKE | HIGH | Login failure rate exceeds threshold |

## Setup SQL

### Create Notification Schema and Config

```sql
CREATE SCHEMA IF NOT EXISTS SECURITY_MONITORING;

CREATE TABLE SECURITY_MONITORING.NOTIFICATION_CONFIG (
  alert_type VARCHAR(100) PRIMARY KEY,
  description VARCHAR(500),
  enabled BOOLEAN DEFAULT FALSE,
  email_enabled BOOLEAN DEFAULT FALSE,
  webhook_enabled BOOLEAN DEFAULT FALSE,
  severity VARCHAR(20) DEFAULT 'MEDIUM',
  threshold_value NUMBER,
  check_interval_minutes NUMBER DEFAULT 15,
  last_checked TIMESTAMP_NTZ,
  created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

INSERT INTO SECURITY_MONITORING.NOTIFICATION_CONFIG 
  (alert_type, description, severity, threshold_value, check_interval_minutes) 
VALUES
  ('ACCOUNTADMIN_GRANT', 'New ACCOUNTADMIN role grant detected', 'CRITICAL', NULL, 5),
  ('ACCOUNT_NETWORK_POLICY_REMOVED', 'Account-level network policy removed', 'CRITICAL', NULL, 5),
  ('PASSWORD_POLICY_REMOVED', 'Account password policy removed or weakened', 'CRITICAL', NULL, 15),
  ('CORTEX_USER_PUBLIC_GRANT', 'CORTEX_USER granted to PUBLIC role', 'CRITICAL', NULL, 15),
  ('ACCOUNTADMIN_COUNT_THRESHOLD', 'ACCOUNTADMIN user count exceeds threshold', 'HIGH', 5, 60),
  ('DORMANT_USER_THRESHOLD', 'Dormant user count exceeds threshold', 'MEDIUM', 50, 1440),
  ('FAILED_LOGIN_SPIKE', 'Login failure rate exceeds threshold', 'HIGH', 5, 15);
```

### Enable Critical Alerts

```sql
UPDATE SECURITY_MONITORING.NOTIFICATION_CONFIG 
SET enabled = TRUE, email_enabled = TRUE, webhook_enabled = TRUE
WHERE severity = 'CRITICAL';
```

### Create Email Integration

```sql
CREATE NOTIFICATION INTEGRATION security_email_aws
  TYPE = EMAIL
  ENABLED = TRUE
  ALLOWED_RECIPIENTS = (
    'security-team@company.com',
    'soc@company.com'
  )
  COMMENT = 'Security alert email notifications';
```

### Create Webhook Integration

```sql
CREATE NETWORK RULE security_webhook_endpoints
  TYPE = HOST_PORT
  VALUE_LIST = (
    'hooks.slack.com:443',
    'outlook.office.com:443',
    'events.pagerduty.com:443'
  )
  MODE = EGRESS;

CREATE EXTERNAL ACCESS INTEGRATION security_webhook_integration
  ALLOWED_NETWORK_RULES = (security_webhook_endpoints)
  ENABLED = TRUE;
```

### Create Alert Log Table

```sql
CREATE TABLE IF NOT EXISTS SECURITY_MONITORING.ALERT_LOG (
  alert_id NUMBER AUTOINCREMENT PRIMARY KEY,
  alert_type VARCHAR(100),
  severity VARCHAR(20),
  message VARCHAR(5000),
  details VARIANT,
  dispatched_at TIMESTAMP_NTZ,
  acknowledged_at TIMESTAMP_NTZ,
  acknowledged_by VARCHAR(255)
);
```

### Create Privilege Escalation Detection Task

```sql
CREATE OR REPLACE TASK SECURITY_MONITORING.DETECT_PRIVILEGE_ESCALATION
  WAREHOUSE = SECURITY_WH
  SCHEDULE = '1 MINUTE'
AS
BEGIN
  FOR rec IN (
    SELECT user_name, query_text, start_time
    FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
    WHERE query_text ILIKE '%GRANT%ROLE%ACCOUNTADMIN%TO%'
      AND query_text NOT ILIKE '%SHOW%'
      AND start_time > DATEADD(minute, -2, CURRENT_TIMESTAMP())
      AND execution_status = 'SUCCESS'
  ) DO
    INSERT INTO SECURITY_MONITORING.ALERT_LOG 
      (alert_type, severity, message, details, dispatched_at)
    VALUES (
      'ACCOUNTADMIN_GRANT',
      'CRITICAL',
      'New ACCOUNTADMIN grant detected. Executed by: ' || rec.user_name,
      OBJECT_CONSTRUCT('executed_by', rec.user_name, 'query', rec.query_text, 'timestamp', rec.start_time),
      CURRENT_TIMESTAMP()
    );
  END FOR;
END;

ALTER TASK SECURITY_MONITORING.DETECT_PRIVILEGE_ESCALATION RESUME;
```

## Notification Channels Reference

| Channel | Integration Type | Use Case |
|---------|-----------------|----------|
| Email | Notification Integration | Security team distribution list |
| Slack | External Access + Webhook | Real-time SOC channel |
| Microsoft Teams | External Access + Webhook | Enterprise collaboration |
| PagerDuty | External Access + Webhook | On-call escalation |

## Checklist

- [ ] SECURITY_MONITORING schema and notification config table created
- [ ] Email notification integration configured
- [ ] Webhook external access integration configured
- [ ] Critical alerts enabled
- [ ] Threshold-based alerts configured with appropriate values
- [ ] Security check task scheduled and running
- [ ] Privilege escalation detection task enabled
- [ ] Alert log table monitored and alerts acknowledged
