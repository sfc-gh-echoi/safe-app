---
name: first-network-policy-audit
description: "Audit Snowflake network policies across accounts. Use when checking network security, IP restrictions, or policy compliance."
---

# Network Policy Audit

## Overview
Audits Snowflake accounts for network policy configuration, identifying security gaps where sensitive data may be exposed without IP restrictions.

## Workflow

### Step 1: Identify Target Account
Ask which Snowflake connection/account to audit. If multiple connections exist, list them:
```bash
grep -E '^\[' ~/.snowflake/connections.toml
```

### Step 2: Verify Connection
Test the connection is working and confirm the account:
```bash
snow connection test -c <connection_name>
snow sql -c <connection_name> -q "SELECT CURRENT_ACCOUNT_NAME(), CURRENT_ORGANIZATION_NAME()"
```

### Step 3: List Network Policies
Query network policies in the account:
```bash
snow sql -c <connection_name> -q "SHOW NETWORK POLICIES"
```

### Step 4: Check Active Account-Level Policy
Determine if a network policy is enforced at the account level:
```sql
SHOW PARAMETERS LIKE 'network_policy' IN ACCOUNT
```

### Step 5: Analyze Policy Details (if policies exist)
For each policy, examine allowed/blocked IPs and network rules:
```sql
DESCRIBE NETWORK POLICY <policy_name>
```

### Step 6: Report Findings
Summarize:
- Total number of network policies
- Which policy (if any) is active at account level
- Number of allowed IPs/network rules
- Security gaps (e.g., no policy = open to any IP)

## Examples

**Input:** "Check network security on Snowhouse"

**Output:**
```
Account: SFCOGSOPS.SNOWHOUSE
Network Policies: 0
Active Policy: None

WARNING: No network policy in effect. Account is accessible from any IP address.

Recommendation: Create a network policy to restrict access to trusted IPs (VPN, office, PrivateLink).
```

## When to Apply
- User asks about network policies, IP restrictions, or network security
- Security audit or compliance check on a Snowflake account
- Checking if an account has proper network access controls
- Comparing network configurations across accounts

## Notes
- Network policy management requires SECURITYADMIN or ACCOUNTADMIN role
- If user lacks permissions to create policies, offer to draft a policy specification for their admin
- Use `snow sql -c <connection>` for reliable connection-specific queries (avoids session caching issues)
