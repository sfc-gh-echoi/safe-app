---
name: org-governance
description: "Organization-level security governance for multi-account environments. Covers GLOBALORGADMIN, Organization Hub, Trust Center, and cross-account security."
---

# Organization-Level Governance Sub-Skill

> **Compliance**: NIST PM-2, PM-10, PM-14 | CIS 1.1, 2.1, 2.5 | SOC 2 CC1.2, CC3.1 | ISO A.5.1, A.6.1 | PCI-DSS 12.1, 12.4

**Prerequisite**: Organization account with GLOBALORGADMIN role and premium views enabled.

## Organization Hub Security Metrics

| Metric Tile | Security Value | Action Triggers |
|-------------|---------------|-----------------|
| Trust Center Violations | Open violations by severity | Week-over-week increase; any Critical violations |
| Scanner Package Coverage | % of accounts with Trust Center scanners | Coverage < 100% indicates unmonitored accounts |
| MFA Progress | Accounts MFA-ready vs. not-ready | Any account not MFA-ready requires immediate action |
| Login Failures by Type | Failed logins categorized (28-day trend) | Spike indicates credential stuffing or misconfiguration |
| Account Admins | All ACCOUNTADMIN users per account | Total count and per-account distribution |
| Dormant Users | Users with no login in 90+ days | Trend increase indicates lifecycle management gaps |

## Assessment Queries

### Cross-Account ACCOUNTADMIN Distribution

```sql
SELECT 
  account_name,
  COUNT(DISTINCT user_name) as accountadmin_count
FROM SNOWFLAKE.ORGANIZATION_USAGE.GRANTS_TO_USERS
WHERE role = 'ACCOUNTADMIN'
  AND deleted_on IS NULL
GROUP BY account_name
ORDER BY accountadmin_count DESC;
```

### Cross-Account Privilege Analysis

```sql
SELECT 
  user_name,
  COUNT(DISTINCT account_name) as accounts_with_admin,
  LISTAGG(DISTINCT account_name, ', ') as account_list
FROM SNOWFLAKE.ORGANIZATION_USAGE.GRANTS_TO_USERS
WHERE role IN ('ACCOUNTADMIN', 'SECURITYADMIN')
  AND deleted_on IS NULL
GROUP BY user_name
HAVING accounts_with_admin > 1
ORDER BY accounts_with_admin DESC;
```

### Organization-Wide MFA Compliance

```sql
SELECT 
  account_name,
  SUM(CASE WHEN has_mfa THEN 1 ELSE 0 END) as mfa_enabled,
  SUM(CASE WHEN NOT has_mfa THEN 1 ELSE 0 END) as mfa_missing,
  ROUND(100.0 * SUM(CASE WHEN has_mfa THEN 1 ELSE 0 END) / COUNT(*), 1) as mfa_percent
FROM SNOWFLAKE.ORGANIZATION_USAGE.USERS
WHERE deleted_on IS NULL
  AND type = 'PERSON'
GROUP BY account_name
ORDER BY mfa_percent ASC;
```

### Organization Dormant Users

```sql
SELECT 
  account_name,
  user_name,
  last_success_login,
  DATEDIFF(day, last_success_login, CURRENT_TIMESTAMP()) as days_inactive
FROM SNOWFLAKE.ORGANIZATION_USAGE.USERS
WHERE deleted_on IS NULL
  AND (last_success_login IS NULL OR last_success_login < DATEADD(day, -90, CURRENT_TIMESTAMP()))
  AND type = 'PERSON'
ORDER BY account_name, days_inactive DESC;
```

## Organization Security Standards

| Control | Standard | Monitoring via Org Hub |
|---------|----------|------------------------|
| MFA | Required for all PERSON users | MFA Progress tile shows 100% |
| ACCOUNTADMIN | ≤5 per account, none as default role | Account Admins tile |
| Password Auth | Prohibited for service accounts | Auth Methods (Legacy Service) tile |
| Trust Center | Security Essentials on all accounts | Scanner Package Coverage tile |
| Dormant Users | Review at 60 days, disable at 90 | Dormant Users tile trend |
| Login Failures | <1% failure rate normal | Login Failures tile % change |

## Weekly Security Review Workflow

1. **Trust Center Violations**: Review all Critical/High severity violations
2. **MFA Readiness**: Ensure 100% account coverage
3. **Admin Sprawl Check**: Review Account Admins and Security Admins tiles
4. **Dormant User Cleanup**: Export dormant users list
5. **Authentication Method Distribution**: Identify password-only users

## Checklist

- [ ] Organization account established with premium views enabled
- [ ] GLOBALORGADMIN role limited to ≤3 users
- [ ] Organization Hub reviewed daily/weekly by security team
- [ ] Trust Center Security Essentials enabled on 100% of accounts
- [ ] Cross-account admin privileges documented and justified
- [ ] Organization-wide MFA compliance at 100%
- [ ] Dormant user lifecycle process enforced org-wide (90-day threshold)
- [ ] Monthly compliance reports generated from Organization Hub
- [ ] New account onboarding includes mandatory security baseline
