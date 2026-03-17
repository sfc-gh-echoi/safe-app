# Snowflake Security Assessment Report

**Account:** VA_DEMO07 (sfsenorthamerica-securitylab2)  
**Platform:** AWS US-EAST-1  
**Edition:** Enterprise (Business Critical features detected)  
**Assessment Date:** 2026-02-11  
**Overall Risk:** **CRITICAL**

---

## Executive Summary

| # | Finding | Current | Best Practice | Risk | Compliance Impact |
|---|---------|---------|---------------|------|-------------------|
| 1 | Excessive ACCOUNTADMIN users | 20 | ≤5 | **CRITICAL** | AC-6, CC6.3, 7.2.2 |
| 2 | ACCOUNTADMIN as default role | 10 users | 0 users | **CRITICAL** | AC-6, CC6.3, 7.2.2 |
| 3 | ACCOUNTADMIN without MFA | 16 users | 0 users | **CRITICAL** | IA-2, CC6.1, 8.4.2 |
| 4 | Low MFA adoption | 14.08% | 100% | **CRITICAL** | IA-2, CC6.1, 8.4.2 |
| 5 | High login failure rate | 70% | <5% | **HIGH** | IA-5, CC6.1, 8.3.6 |
| 6 | No account password policy | None | Configured | **HIGH** | IA-5, CC6.1, 8.3.6 |
| 7 | No account session policy | None | Configured | **MEDIUM** | AC-11, CC6.1, 8.2.8 |
| 8 | Dormant users | 54 | <10 | **MEDIUM** | AC-2, CC6.2, 8.2.6 |
| 9 | Objects owned by ACCOUNTADMIN | 82 | 0 | **MEDIUM** | AC-6, CC6.3, 7.2.2 |

---

## Positive Findings

| Control | Status |
|---------|--------|
| Account network policy | ✅ ACCOUNT_VPN_POLICY_SE configured |
| SCIM with network policy | ✅ OKTA_PROVISIONING has OKTA network policy |
| Periodic data rekeying | ✅ Enabled |
| Masking policies | ✅ 20 policies |
| Row access policies | ✅ 4 policies |
| Data classification | ✅ 171 columns classified |
| CORTEX_USER not on PUBLIC | ✅ Not granted to PUBLIC |

---

## Detailed Findings

### Finding 1: Excessive ACCOUNTADMIN Users (CRITICAL)

**Current State:** 20 users have ACCOUNTADMIN role  
**Best Practice:** ≤5 users  
**Compliance:** NIST AC-6, SOC 2 CC6.3, PCI-DSS 7.2.2

**Business Impact:** Excessive privileged accounts increase attack surface and insider threat risk. Each ACCOUNTADMIN can modify billing, security settings, and access all data.

### Finding 2: ACCOUNTADMIN as Default Role (CRITICAL)

**Current State:** 10 users have ACCOUNTADMIN as their default role  
**Best Practice:** 0 users  

**Affected Users:**
- INTERNAL_STAGE_TEST
- NICK.NIEVES@SNOWFLAKE.COM
- MIKEM
- JAKE_B
- EUGENE
- SNOWSIGHT
- ADMIN
- VLAD
- UMAIR
- GANA

**Business Impact:** Users with ACCOUNTADMIN as default will operate with maximum privileges for all sessions, violating least-privilege principles.

### Finding 3: ACCOUNTADMIN Users Without MFA (CRITICAL)

**Current State:** 16 of 20 ACCOUNTADMIN users (80%) lack MFA  
**Best Practice:** 100% MFA for privileged accounts

**Affected Users:** SNOWSIGHT, UMAIR, VLAD, GANA, ADMIN, JAKE_B, ANOOSHA_C, KEITH, JOHN, WASIMFCTO, EUGENE, TABLEAU, MIKEM, RYANO, JIMONEILL, INTERNAL_STAGE_TEST

### Finding 4: Low Overall MFA Adoption (CRITICAL)

**Current State:** 14.08% (10 of 71 users) have MFA enabled  
**Best Practice:** 100% for human users

### Finding 5: High Login Failure Rate (HIGH)

**Current State:** 70% failure rate (28 of 40 logins in past 7 days)  
**Best Practice:** <5%

**Possible Causes:**
- Credential stuffing attacks
- Misconfigured service accounts
- Expired passwords or certificates

### Finding 6: No Account Password Policy (HIGH)

**Current State:** No password policy configured at account level  
**Best Practice:** NIST 800-63B aligned policy

### Finding 7: No Account Session Policy (MEDIUM)

**Current State:** No session policy configured  
**Best Practice:** Idle timeout ≤60 min (standard), ≤15 min (privileged)

### Finding 8: Dormant Users (MEDIUM)

**Current State:** 54 users with no login in 90+ days  
**Best Practice:** <10 dormant users, review at 60 days, disable at 90

### Finding 9: Objects Owned by ACCOUNTADMIN (MEDIUM)

**Current State:** 82 tables/views owned by ACCOUNTADMIN  
**Best Practice:** 0 - objects should be owned by SYSADMIN or functional roles

---

## Priority Remediation Plan

### P1 - Immediate (24-48 hours)

1. **Revoke unnecessary ACCOUNTADMIN grants**
```sql
-- Review and revoke ACCOUNTADMIN from users who don't need it
REVOKE ROLE ACCOUNTADMIN FROM USER <username>;
```

2. **Change default roles away from ACCOUNTADMIN**
```sql
ALTER USER INTERNAL_STAGE_TEST SET DEFAULT_ROLE = 'PUBLIC';
ALTER USER MIKEM SET DEFAULT_ROLE = 'SYSADMIN';
-- Repeat for all 10 affected users
```

3. **Enforce MFA for ACCOUNTADMIN users**
```sql
-- Create authentication policy requiring MFA
CREATE AUTHENTICATION POLICY admin_mfa_policy
  MFA_AUTHENTICATION_METHODS = ('TOTP')
  MFA_ENROLLMENT = 'REQUIRED';

ALTER USER <admin_user> SET AUTHENTICATION POLICY = admin_mfa_policy;
```

### P2 - Within 30 days

4. **Implement password policy**
```sql
CREATE PASSWORD POLICY enterprise_password_policy
  PASSWORD_MIN_LENGTH = 15
  PASSWORD_MAX_LENGTH = 128
  PASSWORD_MIN_UPPER_CASE_CHARS = 1
  PASSWORD_MIN_LOWER_CASE_CHARS = 1
  PASSWORD_MIN_NUMERIC_CHARS = 1
  PASSWORD_MIN_SPECIAL_CHARS = 1
  PASSWORD_MAX_AGE_DAYS = 365
  PASSWORD_HISTORY = 24
  PASSWORD_MAX_RETRIES = 5
  PASSWORD_LOCKOUT_TIME_MINS = 30;

ALTER ACCOUNT SET PASSWORD POLICY = enterprise_password_policy;
```

5. **Implement session policy**
```sql
CREATE SESSION POLICY standard_session_policy
  SESSION_IDLE_TIMEOUT_MINS = 60
  SESSION_UI_IDLE_TIMEOUT_MINS = 30;

ALTER ACCOUNT SET SESSION POLICY = standard_session_policy;
```

6. **Investigate login failures**
```sql
SELECT user_name, error_message, COUNT(*) as failures
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE is_success = 'NO'
  AND event_timestamp > DATEADD(day, -7, CURRENT_TIMESTAMP())
GROUP BY user_name, error_message
ORDER BY failures DESC;
```

### P3 - Within 90 days

7. **Review and disable dormant users**
```sql
-- List dormant users for review
SELECT name, last_success_login, 
  DATEDIFF(day, last_success_login, CURRENT_TIMESTAMP()) as days_inactive
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS 
WHERE deleted_on IS NULL 
  AND (disabled IS NULL OR disabled::BOOLEAN = FALSE)
  AND (last_success_login IS NULL OR last_success_login < DATEADD(day, -90, CURRENT_TIMESTAMP()))
ORDER BY days_inactive DESC;

-- Disable after review
ALTER USER <username> SET DISABLED = TRUE;
```

8. **Transfer object ownership from ACCOUNTADMIN**
```sql
-- Transfer tables to SYSADMIN
GRANT OWNERSHIP ON ALL TABLES IN SCHEMA <db>.<schema> TO ROLE SYSADMIN;
```

---

## Compliance Gap Summary

| Framework | Gaps | Controls Affected |
|-----------|------|-------------------|
| NIST 800-53 | MFA, password policy, session policy, least privilege | IA-2, IA-5, AC-6, AC-11 |
| SOC 2 | MFA, access control, user lifecycle | CC6.1, CC6.2, CC6.3 |
| PCI-DSS 4.0 | MFA, password policy, privileged access | 7.2.2, 8.3.6, 8.4.2 |
| HIPAA | Access controls, session management | 164.312(a)(1), 164.312(d) |

---

## Next Steps

1. Schedule remediation review meeting
2. Assign owners for each P1 finding
3. Re-assess after P1 remediation (target: 2 weeks)
4. Monthly security posture review thereafter

---

*Report generated by Cortex Code Security Hardening Skill*
