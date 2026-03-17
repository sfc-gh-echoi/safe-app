---
name: identity-access
description: "Identity and Access Management security checks. Covers MFA, SSO/SAML, SCIM, authentication policies, password policies, session policies, and user lifecycle."
---

# Identity & Access Management Sub-Skill

> **Compliance**: NIST IA-2, IA-5, IA-8, AC-2 | CIS 4.1, 4.6, 5.1, 5.2 | SOC 2 CC6.1, CC6.2 | ISO A.9.2, A.9.4 | PCI-DSS 8.2, 8.3 | HIPAA 164.312(d)

## Assessment Queries

### MFA Adoption

```sql
SELECT 
  COUNT(*) as total_users,
  SUM(CASE WHEN has_mfa THEN 1 ELSE 0 END) as mfa_enabled,
  ROUND(100.0 * SUM(CASE WHEN has_mfa THEN 1 ELSE 0 END) / COUNT(*), 2) as mfa_percent
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE deleted_on IS NULL
  AND (disabled IS NULL OR disabled::BOOLEAN = FALSE);
```

**Best Practice**: 100% MFA adoption for human users

### ACCOUNTADMIN Users Without MFA

```sql
SELECT u.name, u.has_mfa, u.default_role
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g 
  ON u.name = g.grantee_name
WHERE g.role = 'ACCOUNTADMIN'
  AND u.has_mfa = FALSE
  AND u.deleted_on IS NULL
  AND g.deleted_on IS NULL;
```

**Best Practice**: 0 ACCOUNTADMIN users without MFA (CRITICAL)

### ACCOUNTADMIN as Default Role

```sql
SELECT name, default_role, email
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE default_role = 'ACCOUNTADMIN'
  AND deleted_on IS NULL;
```

**Best Practice**: 0 users with ACCOUNTADMIN as default role (CRITICAL)

### Dormant Users (90+ days)

```sql
SELECT 
  name,
  email,
  last_success_login,
  DATEDIFF(day, last_success_login, CURRENT_TIMESTAMP()) as days_inactive
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE deleted_on IS NULL
  AND (disabled IS NULL OR disabled::BOOLEAN = FALSE)
  AND (last_success_login IS NULL OR last_success_login < DATEADD(day, -90, CURRENT_TIMESTAMP()))
ORDER BY days_inactive DESC;
```

**Best Practice**: <10 dormant users

### Password Policy Status

```sql
SHOW PARAMETERS LIKE 'PASSWORD_POLICY' IN ACCOUNT;
```

**Best Practice**: Password policy configured

### Session Policy Status

```sql
SHOW PARAMETERS LIKE 'SESSION_POLICY' IN ACCOUNT;
```

**Best Practice**: Session policy configured

### SCIM Integration Security

```sql
SHOW SECURITY INTEGRATIONS;
-- Check for SCIM integrations and their network policies
```

## Remediation SQL

### Create Password Policy

```sql
CREATE PASSWORD POLICY enterprise_password_policy
  PASSWORD_MIN_LENGTH = 15
  PASSWORD_MAX_LENGTH = 128
  PASSWORD_MIN_UPPER_CASE_CHARS = 1
  PASSWORD_MIN_LOWER_CASE_CHARS = 1
  PASSWORD_MIN_NUMERIC_CHARS = 1
  PASSWORD_MIN_SPECIAL_CHARS = 1
  PASSWORD_MAX_AGE_DAYS = 365
  PASSWORD_MIN_AGE_DAYS = 1
  PASSWORD_HISTORY = 24
  PASSWORD_MAX_RETRIES = 5
  PASSWORD_LOCKOUT_TIME_MINS = 30
  COMMENT = 'Aligned with NIST 800-63B';

ALTER ACCOUNT SET PASSWORD POLICY = enterprise_password_policy;
```

### Create Session Policy

```sql
CREATE SESSION POLICY standard_session_policy
  SESSION_IDLE_TIMEOUT_MINS = 60
  SESSION_UI_IDLE_TIMEOUT_MINS = 30
  COMMENT = 'Standard users - balance security and usability';

ALTER ACCOUNT SET SESSION POLICY = standard_session_policy;
```

### Disable Dormant User

```sql
ALTER USER <username> SET DISABLED = TRUE;
```

## Checklist

- [ ] SSO/SAML integrated with enterprise IdP
- [ ] SCIM provisioning with network policy restrictions
- [ ] Authentication policies segmented by user type
- [ ] Password policy aligned with NIST 800-63B
- [ ] Session policies enforce idle timeout
- [ ] MFA required for all human users
- [ ] ACCOUNTADMIN users < 5, none with default role set
