---
name: network-security
description: "Network security controls. Covers network policies, IP allowlisting, private connectivity, and integration-specific network restrictions."
---

# Network Security Sub-Skill

> **Compliance**: NIST SC-7, SC-8, AC-17 | CIS 12.1, 13.1, 13.4 | SOC 2 CC6.6 | ISO A.13.1 | PCI-DSS 1.3, 1.4, 1.5 | HIPAA 164.312(e)(1)

## Assessment Queries

### Account Network Policy

```sql
SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT;
```

**Best Practice**: Network policy configured at account level

### List All Network Policies

```sql
SHOW NETWORK POLICIES;
```

### Network Policy Details

```sql
DESC NETWORK POLICY <policy_name>;
```

### Users Without Network Policy

```sql
SELECT name, email
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE deleted_on IS NULL
  AND (disabled IS NULL OR disabled::BOOLEAN = FALSE)
  AND name NOT IN (
    SELECT user_name FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))
  );
```

### SCIM Integration Network Policy

```sql
SHOW SECURITY INTEGRATIONS;
-- Check TYPE = SCIM integrations for NETWORK_POLICY setting
```

### Private Connectivity Status (Business Critical)

```sql
SELECT SYSTEM$GET_PRIVATELINK_CONFIG();
```

## Remediation SQL

### Create Account Network Policy

```sql
CREATE NETWORK RULE corporate_egress_ips
  TYPE = IPV4
  VALUE_LIST = (
    '203.0.113.0/24',      -- Corporate office 1
    '198.51.100.0/24',     -- Corporate office 2
    '192.0.2.0/24'         -- VPN egress
  )
  MODE = INGRESS
  COMMENT = 'Corporate network egress points';

CREATE NETWORK POLICY account_baseline_policy
  ALLOWED_NETWORK_RULE_LIST = ('corporate_egress_ips')
  COMMENT = 'Baseline: All access must originate from corporate network';

ALTER ACCOUNT SET NETWORK_POLICY = account_baseline_policy;
```

### Create SCIM Network Policy

```sql
CREATE NETWORK RULE scim_okta_ips
  TYPE = IPV4
  VALUE_LIST = (
    '100.96.16.0/20',
    '100.96.32.0/20',
    '100.96.48.0/20'
  )
  MODE = INGRESS
  COMMENT = 'Okta SCIM egress IP ranges';

CREATE NETWORK POLICY SCIM_NETWORK_POLICY
  ALLOWED_NETWORK_RULE_LIST = ('scim_okta_ips')
  COMMENT = 'Restricts SCIM API access to Okta infrastructure only';
```

### Service Account Network Policy

```sql
CREATE NETWORK RULE etl_server_ips
  TYPE = IPV4
  VALUE_LIST = ('10.0.1.50/32', '10.0.1.51/32')
  MODE = INGRESS;

CREATE NETWORK POLICY etl_service_policy
  ALLOWED_NETWORK_RULE_LIST = ('etl_server_ips');

ALTER USER etl_service_account SET NETWORK_POLICY = etl_service_policy;
```

## Checklist

- [ ] Account-level network policy enforced
- [ ] User-level policies for service accounts (IP-restricted)
- [ ] Integration-specific policies for SCIM/OAuth (IdP IPs only)
- [ ] Private connectivity enabled for regulated workloads (Business Critical)
- [ ] Internal stage public access blocked (Azure/AWS)
