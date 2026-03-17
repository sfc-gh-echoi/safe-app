---
name: snowflake-security-hardening
version: "2.0.0"
last_updated: "2026-02-11"
description: "Guide administrators through hardening Snowflake account security posture with best practices for authentication, networking, data protection, and RBAC."
triggers:
  - security audit
  - security assessment
  - harden snowflake
  - security hardening
  - compliance review
  - SOC 2 preparation
  - PCI-DSS compliance
  - HIPAA compliance
  - security posture
  - ACCOUNTADMIN audit
  - network policy review
  - MFA enforcement
  - privilege escalation
  - dormant users
  - SCIM security
  - Cortex governance
  - password policy
  - session policy
---

# Snowflake Security Hardening Guide

## Overview

This skill provides a comprehensive security hardening framework for Snowflake environments, aligned with industry standards including NIST 800-53, CIS Controls, ISO 27001, and SOC 2 Type II requirements.

### Sub-Skills

This skill is organized into focused sub-skills for modularity:

| Sub-Skill | Purpose | Load When |
|-----------|---------|-----------|
| `identity-access/SKILL.md` | MFA, SSO, SCIM, password/session policies | IAM assessment or remediation |
| `network-security/SKILL.md` | Network policies, IP allowlisting, private connectivity | Network security checks |
| `data-protection/SKILL.md` | Encryption, masking, row access policies | Data protection assessment |
| `ai-governance/SKILL.md` | Cortex roles, external AI security | AI/ML workload governance |
| `audit-monitoring/SKILL.md` | SIEM integration, security alerts | Audit/monitoring setup |
| `org-governance/SKILL.md` | Multi-account security, Organization Hub | Enterprise org governance |
| `notifications/SKILL.md` | Email/webhook alerting setup | Real-time alerting |
| `templates/report-template.md` | Verbose output format | All assessments |

### Security Philosophy

This guide follows **Zero Trust principles**: never trust, always verify. Every access request is validated regardless of source, and least-privilege access is enforced at every layer.

| Threat Category | Controls Addressed |
|-----------------|-------------------|
| Credential Compromise | MFA, SSO federation, password policies, key rotation |
| Insider Threat | RBAC, separation of duties, audit logging, session controls |
| Data Exfiltration | Network policies, stage controls, masking, egress restrictions |
| Lateral Movement | Role hierarchy limits, network segmentation, least privilege |
| Supply Chain Risk | Integration controls, SCIM hardening, OAuth restrictions |

### Compliance Mapping

| Control Domain | NIST 800-53 | CIS Controls v8 | SOC 2 TSC | ISO 27001 | PCI-DSS 4.0 | HIPAA |
|---------------|-------------|-----------------|-----------|-----------|-------------|-------|
| Authentication | IA-2, IA-5, IA-8 | 4.1, 4.6, 5.2 | CC6.1 | A.9.2, A.9.4 | 8.2, 8.3 | 164.312(d) |
| Access Control | AC-2, AC-3, AC-6 | 5.1, 5.4, 6.1 | CC6.2, CC6.3 | A.9.1, A.9.2 | 7.1, 7.2 | 164.312(a)(1) |
| Network Security | SC-7, SC-8 | 12.1, 13.1 | CC6.6 | A.13.1 | 1.3, 1.4 | 164.312(e)(1) |
| Data Protection | SC-12, SC-28 | 3.11, 3.12 | CC6.7 | A.10.1, A.18.1 | 3.4, 3.5 | 164.312(a)(2)(iv) |
| Audit & Monitoring | AU-2, AU-3, AU-6 | 8.2, 8.5 | CC7.2 | A.12.4 | 10.1, 10.2 | 164.312(b) |
| Org Governance | PM-2, PM-10 | 1.1, 2.1 | CC1.2, CC3.1 | A.5.1, A.6.1 | 12.1 | 164.308(a)(1) |
| AI Governance | AC-6, AU-6, SC-7 | 3.3, 4.1, 13.1 | CC6.1, CC7.2 | A.9.4, A.12.4 | 7.2, 10.2 | 164.312(a)(1) |
| Notifications | AU-5, IR-6, SI-4 | 8.11, 17.4, 17.9 | CC7.3, CC7.4 | A.12.4, A.16.1 | 10.7, 12.10 | 164.308(a)(6) |

---

## Workflow

### Step 1: Determine Snowflake Edition

**IMPORTANT: Always prompt the user for their Snowflake edition before proceeding.**

Use the `ask_user_question` tool:
```
Question: "What Snowflake edition is this account using?"
Options:
- Standard: Core security features (network policies, MFA, RBAC)
- Enterprise: Adds column/row-level security, data classification, advanced governance
- Business Critical: Adds private connectivity, BYOK (Tri-Secret Secure), HIPAA/PCI eligibility
```

**Edition Feature Matrix:**

| Feature | Standard | Enterprise | Business Critical |
|---------|----------|------------|-------------------|
| Network Policies | ✅ | ✅ | ✅ |
| MFA | ✅ | ✅ | ✅ |
| RBAC | ✅ | ✅ | ✅ |
| Object Tagging | ❌ | ✅ | ✅ |
| Masking Policies | ❌ | ✅ | ✅ |
| Row Access Policies | ❌ | ✅ | ✅ |
| Data Classification | ❌ | ✅ | ✅ |
| Private Connectivity | ❌ | ❌ | ✅ |
| Tri-Secret Secure (BYOK) | ❌ | ❌ | ✅ |
| HIPAA/PCI BAA eligible | ❌ | ❌ | ✅ |

---

### Step 2: Run Security Assessment

Load sub-skills based on assessment scope:

**Full Assessment (recommended):**
1. Load `identity-access/SKILL.md` - Run all IAM queries
2. Load `network-security/SKILL.md` - Run network policy queries
3. Load `data-protection/SKILL.md` - Run data protection queries
4. Load `ai-governance/SKILL.md` - Run AI governance queries
5. Load `audit-monitoring/SKILL.md` - Run audit queries

**Focused Assessment:**
- IAM only: Load `identity-access/SKILL.md`
- Network only: Load `network-security/SKILL.md`
- Data protection only: Load `data-protection/SKILL.md`
- AI governance only: Load `ai-governance/SKILL.md`
- Organization governance: Load `org-governance/SKILL.md`

---

### Step 3: Generate Report

**IMPORTANT: Always output the FULL verbose report format. Load `templates/report-template.md` for the exact format.**

### Standard Findings Reference

| Finding | Best Practice | Risk | Compliance |
|---------|---------------|------|------------|
| ACCOUNTADMIN count | ≤5 users | CRITICAL | AC-6, CC6.3, 7.2.2 |
| ACCOUNTADMIN as default role | 0 users | CRITICAL | AC-6, CC6.3, 7.2.2 |
| ACCOUNTADMIN without MFA | 0 users | CRITICAL | IA-2, CC6.1, 8.4.2 |
| Overall MFA adoption | 100% | CRITICAL | IA-2, CC6.1, 8.4.2 |
| Login failure rate | <5% | HIGH | IA-5, CC6.1, 8.3.6 |
| Password policy | Configured | HIGH | IA-5, CC6.1, 8.3.6 |
| Session policy | Configured | MEDIUM | AC-11, CC6.1, 8.2.8 |
| Dormant users (90+ days) | <10 | MEDIUM | AC-2, CC6.2, 8.2.6 |
| Objects owned by ACCOUNTADMIN | 0 | MEDIUM | AC-6, CC6.3, 7.2.2 |
| Network policy | Configured | HIGH | SC-7, CC6.6, 1.3.1 |
| SCIM network policy | Configured | HIGH | SC-7, CC6.6, 1.4.2 |
| Data rekeying | Enabled | MEDIUM | SC-12, CC6.7, 3.5.3 |
| CORTEX_USER to PUBLIC | Not granted | CRITICAL | AC-6, CC6.3, 7.2.2 |

---

### Step 4: Remediation

Load the appropriate sub-skill for remediation SQL:

- IAM remediation → `identity-access/SKILL.md`
- Network remediation → `network-security/SKILL.md`
- Data protection remediation → `data-protection/SKILL.md`
- AI governance remediation → `ai-governance/SKILL.md`
- Set up alerting → `notifications/SKILL.md`

---

## Quick Assessment Queries

These are the core queries for a rapid assessment. For detailed queries, load the sub-skills.

### ACCOUNTADMIN Count

```sql
SELECT COUNT(DISTINCT grantee_name) as accountadmin_count
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
WHERE role = 'ACCOUNTADMIN'
  AND deleted_on IS NULL;
```

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

### ACCOUNTADMIN Without MFA

```sql
SELECT u.name, u.has_mfa
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g 
  ON u.name = g.grantee_name
WHERE g.role = 'ACCOUNTADMIN'
  AND u.has_mfa = FALSE
  AND u.deleted_on IS NULL
  AND g.deleted_on IS NULL;
```

### ACCOUNTADMIN as Default Role

```sql
SELECT name, default_role
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE default_role = 'ACCOUNTADMIN'
  AND deleted_on IS NULL;
```

### Dormant Users

```sql
SELECT name, last_success_login,
  DATEDIFF(day, last_success_login, CURRENT_TIMESTAMP()) as days_inactive
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE deleted_on IS NULL
  AND (disabled IS NULL OR disabled::BOOLEAN = FALSE)
  AND (last_success_login IS NULL OR last_success_login < DATEADD(day, -90, CURRENT_TIMESTAMP()));
```

### Network Policy Status

```sql
SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT;
```

### Password Policy Status

```sql
SHOW PARAMETERS LIKE 'PASSWORD_POLICY' IN ACCOUNT;
```

### Session Policy Status

```sql
SHOW PARAMETERS LIKE 'SESSION_POLICY' IN ACCOUNT;
```

### Data Rekeying Status

```sql
SHOW PARAMETERS LIKE 'PERIODIC_DATA_REKEYING' IN ACCOUNT;
```

### Login Failure Rate

```sql
SELECT 
  ROUND(100.0 * SUM(CASE WHEN is_success = 'NO' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) as failure_rate
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE event_timestamp > DATEADD(day, -7, CURRENT_TIMESTAMP());
```

### Objects Owned by ACCOUNTADMIN

```sql
SELECT COUNT(*) as objects_count
FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES
WHERE table_owner = 'ACCOUNTADMIN'
  AND deleted IS NULL;
```

### Masking Policies (Enterprise+)

```sql
SELECT COUNT(*) as masking_policy_count
FROM SNOWFLAKE.ACCOUNT_USAGE.MASKING_POLICIES
WHERE deleted IS NULL;
```

### CORTEX_USER to PUBLIC Check

```sql
SELECT COUNT(*) as cortex_public_grants
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
WHERE name = 'CORTEX_USER'
  AND grantee_name = 'PUBLIC'
  AND deleted_on IS NULL;
```

---

## Security Checklist

### Identity & Access Management
- [ ] SSO/SAML integrated with enterprise IdP
- [ ] SCIM provisioning with network policy restrictions
- [ ] Password policy aligned with NIST 800-63B
- [ ] Session policies enforce idle timeout
- [ ] MFA required for all human users
- [ ] ACCOUNTADMIN users < 5, none with default role set

### Network Security
- [ ] Account-level network policy enforced
- [ ] User-level policies for service accounts (IP-restricted)
- [ ] Private connectivity enabled for regulated workloads (Business Critical)

### Data Protection
- [ ] Periodic data rekeying enabled (Enterprise+)
- [ ] Masking policies applied to PII/sensitive columns
- [ ] Row access policies for multi-tenant/regional segmentation

### AI Governance
- [ ] Cortex roles follow least privilege
- [ ] CORTEX_USER NOT granted to PUBLIC
- [ ] External AI egress restricted to approved endpoints

### Audit & Monitoring
- [ ] SIEM integration configured
- [ ] Critical alerts defined
- [ ] Regular access reviews scheduled

---

## When to Apply

- New Snowflake account deployment
- Pre-production security review
- Annual security audit / penetration test preparation
- Compliance certification (SOC 2, HIPAA, PCI-DSS, FedRAMP)
- Post-incident hardening
- Edition upgrade
- AI/ML workload onboarding
- Organization expansion
- Security operations maturity

---

## Changelog

### v2.0.0 (2026-02-11)

**Refactored into Sub-Skills:**
- Split monolithic skill into 7 focused sub-skills
- Created `identity-access/SKILL.md` - IAM controls
- Created `network-security/SKILL.md` - Network policies
- Created `data-protection/SKILL.md` - Encryption/masking/RAP
- Created `ai-governance/SKILL.md` - Cortex governance
- Created `audit-monitoring/SKILL.md` - SIEM/alerting
- Created `org-governance/SKILL.md` - Multi-account governance
- Created `notifications/SKILL.md` - Email/webhook alerting
- Created `templates/report-template.md` - Verbose output format
- Main SKILL.md now orchestrates sub-skills

### v1.3.0 (2026-02-11)
- Added complete verbose report template
- Added "Standard Findings Reference" table

### v1.2.0 (2026-02-11)
- Step 1 now requires prompting user for Snowflake edition

### v1.1.0 (2026-02-11)
- Fixed 7 SQL syntax errors (column names, VARIANT handling)
- All 18 core assessment queries tested and validated

### v1.0.0 (Initial)
- Initial security hardening framework
