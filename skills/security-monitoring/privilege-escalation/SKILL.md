---
name: privilege-escalation
description: "Detect privilege escalation attempts in Snowflake. Use when: investigating unauthorized access, role changes, suspicious grants, ACCOUNTADMIN abuse, self-grants, new users, backdoor accounts, or RBAC violations. Supports both ACCOUNT_USAGE and ORGANIZATION_USAGE. Triggers: privilege escalation, role grant, ACCOUNTADMIN, SECURITYADMIN, SYSADMIN, grant to self, create user, alter user, create role, suspicious grant, backdoor, unauthorized access, RBAC audit, who granted, privilege abuse."
---

# Privilege Escalation Detection

Analyze Snowflake activity for privilege escalation patterns and unauthorized access changes.

## Workflow

### Step 1: Select Detection Scope

**Ask user (Question 1 - Timeframe):**
```
What timeframe should I analyze?
1. Last 24 hours
2. Last 7 days
3. Last 30 days
4. Custom date range
```

**Ask user (Question 2 - Scope):**
```
What scope should I analyze?
1. ACCOUNT_USAGE (current account only)
2. ORGANIZATION_USAGE (all accounts in organization - requires ORGADMIN)
```

**⚠️ STOP**: Wait for user response.

**Requirements:**
- ACCOUNT_USAGE: Requires `IMPORTED PRIVILEGES` on SNOWFLAKE database
- ORGANIZATION_USAGE: Requires `ORGADMIN` role or `USAGE` on `SNOWFLAKE.ORGANIZATION_USAGE`

### Step 2: Run Detection Queries

Execute these queries replacing:
- `{{DAYS}}` with the selected timeframe
- `{{SCHEMA}}` with either `ACCOUNT_USAGE` or `ORGANIZATION_USAGE`

**For ORGANIZATION_USAGE queries:**
- Add `account_name` to SELECT columns
- Add `account_name` to GROUP BY clauses where applicable
- Include `account_name` in output reports

**Note:** All queries below show ACCOUNT_USAGE syntax. For ORGANIZATION_USAGE:
- Replace `SNOWFLAKE.ACCOUNT_USAGE` with `SNOWFLAKE.ORGANIZATION_USAGE`
- Add `account_name` as the first column in SELECT statements

---

### User Account Changes

#### 2a: New User Creation

```sql
SELECT
    query_id,
    user_name as created_by,
    role_name,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'CREATE_USER'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

#### 2b: User Modifications (Password, Properties, Defaults)

```sql
SELECT
    query_id,
    user_name as modified_by,
    role_name,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'ALTER_USER'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

#### 2c: User Deletions (Potential Cover-Up)

```sql
SELECT
    query_id,
    user_name as deleted_by,
    role_name,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'DROP_USER'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

---

### Role Changes

#### 2d: New Role Creation

```sql
SELECT
    query_id,
    user_name as created_by,
    role_name as using_role,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'CREATE_ROLE'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

#### 2e: Role Modifications

```sql
SELECT
    query_id,
    user_name as modified_by,
    role_name as using_role,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'ALTER_ROLE'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

#### 2f: Role Deletions

```sql
SELECT
    query_id,
    user_name as deleted_by,
    role_name as using_role,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'DROP_ROLE'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

---

### Privileged Role Grants (CRITICAL)

#### 2g: ACCOUNTADMIN Grants

```sql
SELECT
    query_id,
    user_name as granted_by,
    role_name as using_role,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE LOWER(query_text) LIKE '%grant%accountadmin%'
  AND query_type = 'GRANT'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

#### 2h: SECURITYADMIN Grants

```sql
SELECT
    query_id,
    user_name as granted_by,
    role_name as using_role,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE LOWER(query_text) LIKE '%grant%securityadmin%'
  AND query_type = 'GRANT'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

#### 2i: SYSADMIN Grants

```sql
SELECT
    query_id,
    user_name as granted_by,
    role_name as using_role,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE LOWER(query_text) LIKE '%grant%sysadmin%'
  AND query_type = 'GRANT'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

#### 2j: USERADMIN Grants

```sql
SELECT
    query_id,
    user_name as granted_by,
    role_name as using_role,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE LOWER(query_text) LIKE '%grant%useradmin%'
  AND query_type = 'GRANT'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

#### 2k: All Privileged Role Grants Combined

```sql
SELECT
    query_id,
    user_name as granted_by,
    role_name as using_role,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'GRANT'
  AND (
    LOWER(query_text) LIKE '%grant%accountadmin%'
    OR LOWER(query_text) LIKE '%grant%securityadmin%'
    OR LOWER(query_text) LIKE '%grant%sysadmin%'
    OR LOWER(query_text) LIKE '%grant%useradmin%'
    OR LOWER(query_text) LIKE '%grant%orgadmin%'
  )
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

---

### Self-Grants (Suspicious Pattern)

#### 2l: Grants Where User Grants to Themselves

```sql
SELECT
    query_id,
    user_name as granted_by,
    role_name as using_role,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'GRANT'
  AND (
    LOWER(query_text) LIKE '%to user ' || LOWER(user_name) || '%'
    OR LOWER(query_text) LIKE '%to user "' || LOWER(user_name) || '"%'
  )
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

#### 2m: Self-Grants via GRANTS_TO_USERS View

```sql
SELECT
    grantee_name,
    role,
    granted_by,
    created_on
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
WHERE grantee_name = granted_by
  AND created_on >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
  AND deleted_on IS NULL
ORDER BY created_on DESC;
```

---

### All Grant Activity

#### 2n: All GRANT Statements

```sql
SELECT
    query_id,
    user_name as granted_by,
    role_name as using_role,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'GRANT'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

#### 2o: All REVOKE Statements

```sql
SELECT
    query_id,
    user_name as revoked_by,
    role_name as using_role,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'REVOKE'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

#### 2p: Grants with ADMIN OPTION (Can Re-Grant)

```sql
SELECT
    query_id,
    user_name as granted_by,
    role_name as using_role,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'GRANT'
  AND LOWER(query_text) LIKE '%with grant option%'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

---

### Ownership Changes

#### 2q: Ownership Transfers

```sql
SELECT
    query_id,
    user_name as transferred_by,
    role_name as using_role,
    LEFT(query_text, 300) as query_preview,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE (
    LOWER(query_text) LIKE '%grant ownership%'
    OR LOWER(query_text) LIKE '%transfer ownership%'
  )
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

---

### Current State Audit

#### 2r: Current ACCOUNTADMIN Users

```sql
SELECT DISTINCT
    grantee_name as user_name,
    granted_by,
    created_on
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
WHERE role = 'ACCOUNTADMIN'
  AND deleted_on IS NULL
ORDER BY created_on DESC;
```

#### 2s: Current SECURITYADMIN Users

```sql
SELECT DISTINCT
    grantee_name as user_name,
    granted_by,
    created_on
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
WHERE role = 'SECURITYADMIN'
  AND deleted_on IS NULL
ORDER BY created_on DESC;
```

#### 2t: Users with Multiple Privileged Roles

```sql
SELECT
    grantee_name as user_name,
    LISTAGG(role, ', ') as privileged_roles,
    COUNT(*) as role_count
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
WHERE role IN ('ACCOUNTADMIN', 'SECURITYADMIN', 'SYSADMIN', 'USERADMIN', 'ORGADMIN')
  AND deleted_on IS NULL
GROUP BY grantee_name
HAVING COUNT(*) > 1
ORDER BY role_count DESC;
```

#### 2u: Recently Created Users (Potential Backdoors)

```sql
SELECT
    name,
    login_name,
    created_on,
    default_role,
    has_password,
    has_rsa_public_key,
    disabled,
    ext_authn_uid
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE created_on >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
  AND deleted_on IS NULL
ORDER BY created_on DESC;
```

#### 2v: Service Accounts (Non-Human Identities)

```sql
SELECT
    name,
    login_name,
    created_on,
    default_role,
    has_password,
    has_rsa_public_key,
    last_success_login,
    disabled
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE (
    LOWER(name) LIKE '%svc%'
    OR LOWER(name) LIKE '%service%'
    OR LOWER(name) LIKE '%bot%'
    OR LOWER(name) LIKE '%api%'
    OR LOWER(name) LIKE '%etl%'
    OR LOWER(name) LIKE '%pipeline%'
    OR has_rsa_public_key = TRUE
  )
  AND deleted_on IS NULL
ORDER BY created_on DESC;
```

---

### Failed Privilege Operations (Blocked Attempts)

#### 2w: Failed GRANT Attempts

```sql
SELECT
    query_id,
    user_name as attempted_by,
    role_name as using_role,
    LEFT(query_text, 300) as query_preview,
    error_message,
    start_time
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'GRANT'
  AND execution_status = 'FAIL'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

#### 2x: Failed User/Role Creation Attempts

```sql
SELECT
    query_id,
    user_name as attempted_by,
    role_name as using_role,
    query_type,
    LEFT(query_text, 300) as query_preview,
    error_message,
    start_time
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type IN ('CREATE_USER', 'CREATE_ROLE', 'ALTER_USER', 'ALTER_ROLE')
  AND execution_status = 'FAIL'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

---

### Step 3: Analyze Results

For each finding, evaluate:

| Risk Factor | High Risk Indicator |
|-------------|---------------------|
| Privileged Role | ACCOUNTADMIN, SECURITYADMIN, ORGADMIN grants |
| Self-Grant | User grants privileges to themselves |
| After Hours | Changes outside business hours |
| Unusual Actor | Non-admin user making grants |
| ADMIN OPTION | Grant includes WITH GRANT OPTION |
| Ownership | Ownership transferred to suspicious role |
| New User | User created with privileged default role |
| Service Account | New service account with broad access |
| Failed Attempts | Multiple failed grant attempts (probing) |
| Rapid Changes | Many grants in short timeframe |
| Backdoor Pattern | New user + privileged grant + no MFA |

---

### Step 4: Present Findings

**⚠️ MANDATORY CHECKPOINT**: Present summary before recommendations.

**For ACCOUNT_USAGE:**
```
## Privilege Escalation Detection Summary

**Timeframe**: [date range]
**Scope**: Current Account
**Total suspicious events**: [count]

### Critical Findings (Privileged Role Grants)
[ACCOUNTADMIN, SECURITYADMIN, SYSADMIN grants]

### High-Risk Findings (Self-Grants, Ownership Changes)
[Self-grants, ownership transfers]

### Medium-Risk Findings (User/Role Changes)
[New users, role modifications]

### Failed Attempts (Potential Probing)
[Failed grants, blocked operations]

### Users with Excessive Privileges
[Users with multiple admin roles]
```

**For ORGANIZATION_USAGE:**
```
## Privilege Escalation Detection Summary

**Timeframe**: [date range]
**Scope**: Organization (all accounts)
**Total suspicious events**: [count]

### Critical Findings (Privileged Role Grants)
[ACCOUNTADMIN, SECURITYADMIN, SYSADMIN grants - include account_name]

### High-Risk Findings (Self-Grants, Ownership Changes)
[Self-grants, ownership transfers - include account_name]

### Findings by Account
[Aggregate by account_name]

### Medium-Risk Findings (User/Role Changes)
[New users, role modifications - include account_name]

### Failed Attempts (Potential Probing)
[Failed grants, blocked operations - include account_name]

### Users with Excessive Privileges
[Users with multiple admin roles - include account_name]
```

---

### Step 5: Recommend Actions

Based on findings, suggest:
- Privileged role grants to review and potentially revoke
- Self-grants to investigate and remove
- New users to verify legitimacy
- Service accounts to audit
- Ownership transfers to validate
- Failed attempts to correlate with other activity
- MFA enforcement for privileged users
- Access reviews to schedule
- (For ORGANIZATION_USAGE) Accounts requiring immediate attention

**⚠️ STOP**: Wait for user to decide on next steps.

---

## Stopping Points

- ✋ Step 1: After scope selection
- ✋ Step 4: After presenting findings
- ✋ Step 5: After recommendations

---

## Output

Summary report of privilege escalation activity with risk-ranked findings and remediation recommendations.

**ORGANIZATION_USAGE outputs include:**
- Account name in all findings
- Cross-account analysis
- Account-level aggregations
