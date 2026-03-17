---
name: data-protection
description: "Data protection controls. Covers encryption, masking policies, row access policies, data classification, and key management."
---

# Data Protection Sub-Skill

> **Compliance**: NIST SC-12, SC-28, SC-13 | CIS 3.11, 3.12 | SOC 2 CC6.7 | ISO A.10.1, A.18.1 | PCI-DSS 3.4, 3.5, 4.1 | HIPAA 164.312(a)(2)(iv), 164.312(e)(2)(ii)

## Assessment Queries

### Periodic Data Rekeying Status

```sql
SHOW PARAMETERS LIKE 'PERIODIC_DATA_REKEYING' IN ACCOUNT;
```

**Best Practice**: Enabled (Enterprise+)

### Masking Policies Count

```sql
SELECT COUNT(*) as masking_policy_count
FROM SNOWFLAKE.ACCOUNT_USAGE.MASKING_POLICIES
WHERE deleted IS NULL;
```

**Best Practice**: >0 masking policies for sensitive data

### Row Access Policies Count

```sql
SELECT COUNT(*) as row_access_policy_count
FROM SNOWFLAKE.ACCOUNT_USAGE.ROW_ACCESS_POLICIES
WHERE deleted IS NULL;
```

**Best Practice**: Row access policies for multi-tenant/segmented data

### Tags for Data Classification

```sql
SELECT COUNT(*) as tag_count
FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
WHERE tag_database = 'SNOWFLAKE' 
  AND tag_schema = 'CORE';
```

### Objects Owned by ACCOUNTADMIN

```sql
SELECT table_catalog, table_schema, table_name, table_owner
FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES
WHERE table_owner = 'ACCOUNTADMIN'
  AND deleted IS NULL;
```

**Best Practice**: 0 objects owned by ACCOUNTADMIN

## Remediation SQL

### Enable Periodic Data Rekeying

```sql
ALTER ACCOUNT SET PERIODIC_DATA_REKEYING = TRUE;
```

### Create Tag-Based Masking

```sql
CREATE TAG pii_classification
  ALLOWED_VALUES 'SSN', 'EMAIL', 'PHONE', 'ADDRESS', 'DOB'
  COMMENT = 'PII data classification for masking policy binding';

CREATE MASKING POLICY ssn_mask AS (val STRING) RETURNS STRING ->
  CASE
    WHEN CURRENT_ROLE() IN ('PII_FULL_ACCESS', 'COMPLIANCE_ROLE') THEN val
    WHEN CURRENT_ROLE() IN ('ANALYST_ROLE') THEN 'XXX-XX-' || RIGHT(val, 4)
    ELSE '***-**-****'
  END
  COMMENT = 'SSN masking: full access for compliance, partial for analysts';

ALTER TAG pii_classification SET MASKING POLICY ssn_mask;

ALTER TABLE customers MODIFY COLUMN ssn SET TAG pii_classification = 'SSN';
```

### Create Row Access Policy

```sql
CREATE TABLE data_entitlements (
  role_name VARCHAR,
  region VARCHAR,
  business_unit VARCHAR,
  access_level VARCHAR
);

CREATE ROW ACCESS POLICY regional_data_access AS (region_col VARCHAR) RETURNS BOOLEAN ->
  EXISTS (
    SELECT 1 FROM data_entitlements
    WHERE role_name = CURRENT_ROLE()
      AND region = region_col
      AND access_level IN ('FULL', 'RESTRICTED')
  )
  COMMENT = 'Restrict data access by region based on entitlement table';

ALTER TABLE sales ADD ROW ACCESS POLICY regional_data_access ON (region);
```

### Transfer Object Ownership

```sql
GRANT OWNERSHIP ON TABLE <database>.<schema>.<table> TO ROLE <appropriate_role>;
```

## Checklist

- [ ] Periodic data rekeying enabled (Enterprise+)
- [ ] Tri-Secret Secure configured (Business Critical regulated)
- [ ] Masking policies applied to PII/sensitive columns
- [ ] Tag-based masking for scalable governance
- [ ] Row access policies for multi-tenant/regional segmentation
- [ ] Data classification automated
- [ ] No objects owned by ACCOUNTADMIN
