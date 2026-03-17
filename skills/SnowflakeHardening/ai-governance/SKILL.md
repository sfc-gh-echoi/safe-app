---
name: ai-governance
description: "AI and Cortex governance controls. Covers Cortex database roles, external AI integration security, and AI usage monitoring."
---

# AI Governance Sub-Skill

> **Compliance**: NIST AC-6, AU-6, SC-7 | CIS 3.3, 4.1, 13.1 | SOC 2 CC6.1, CC7.2 | ISO A.9.4, A.12.4 | PCI-DSS 7.2, 10.2

## Cortex Database Role Hierarchy

| Database Role | Access Scope | Risk Level |
|--------------|--------------|------------|
| `SNOWFLAKE.CORTEX_USER` | Full Cortex (LLMs, embeddings, Analyst, Search) | Highest |
| `SNOWFLAKE.CORTEX_EMBED_USER` | Embedding functions only | Low |
| `SNOWFLAKE.CORTEX_ANALYST_USER` | Text-to-SQL via Cortex Analyst | Medium |
| `SNOWFLAKE.CORTEX_AGENTS_USER` | Analyst + Search for agents | Medium-High |

## Assessment Queries

### CORTEX_USER Grants to PUBLIC

```sql
SELECT *
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
WHERE name = 'CORTEX_USER'
  AND grantee_name = 'PUBLIC'
  AND deleted_on IS NULL;
```

**Best Practice**: CORTEX_USER should NOT be granted to PUBLIC (CRITICAL)

### External AI Function Usage

```sql
SELECT 
  user_name,
  role_name,
  query_text,
  EXTERNAL_FUNCTION_TOTAL_INVOCATIONS,
  start_time
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE EXTERNAL_FUNCTION_TOTAL_INVOCATIONS > 0
  AND start_time > DATEADD(day, -7, CURRENT_TIMESTAMP())
ORDER BY start_time DESC;
```

### Cortex Usage Patterns

```sql
SELECT 
  user_name,
  role_name,
  DATE_TRUNC('hour', start_time) as hour,
  CASE 
    WHEN query_text ILIKE '%COMPLETE%' OR query_text ILIKE '%SUMMARIZE%' THEN 'LLM_GENERATION'
    WHEN query_text ILIKE '%EMBED_TEXT%' THEN 'EMBEDDING'
    WHEN query_text ILIKE '%CORTEX_SEARCH%' THEN 'SEARCH'
    WHEN query_text ILIKE '%ANALYST%' THEN 'TEXT_TO_SQL'
    ELSE 'OTHER_CORTEX'
  END as ai_operation_type,
  COUNT(*) as operation_count
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_text ILIKE '%SNOWFLAKE.CORTEX%'
  AND start_time > DATEADD(day, -30, CURRENT_TIMESTAMP())
GROUP BY 1, 2, 3, 4;
```

## Remediation SQL

### Create Tiered AI Roles

```sql
CREATE ROLE AI_EMBEDDING_ROLE 
  COMMENT = 'Embedding operations for search/RAG - no content generation';
GRANT DATABASE ROLE SNOWFLAKE.CORTEX_EMBED_USER TO ROLE AI_EMBEDDING_ROLE;

CREATE ROLE AI_ANALYST_ROLE 
  COMMENT = 'Text-to-SQL via Cortex Analyst - bounded by data access RBAC';
GRANT DATABASE ROLE SNOWFLAKE.CORTEX_ANALYST_USER TO ROLE AI_ANALYST_ROLE;

CREATE ROLE AI_AGENT_ROLE 
  COMMENT = 'Agentic AI workflows - requires security review for each use case';
GRANT DATABASE ROLE SNOWFLAKE.CORTEX_AGENTS_USER TO ROLE AI_AGENT_ROLE;

CREATE ROLE AI_DEVELOPER_ROLE 
  COMMENT = 'Full Cortex access - requires AI governance approval';
GRANT DATABASE ROLE SNOWFLAKE.CORTEX_USER TO ROLE AI_DEVELOPER_ROLE;

GRANT ROLE AI_EMBEDDING_ROLE TO ROLE AI_ANALYST_ROLE;
GRANT ROLE AI_ANALYST_ROLE TO ROLE AI_AGENT_ROLE;
GRANT ROLE AI_AGENT_ROLE TO ROLE AI_DEVELOPER_ROLE;
```

### Revoke CORTEX_USER from PUBLIC

```sql
REVOKE DATABASE ROLE SNOWFLAKE.CORTEX_USER FROM ROLE PUBLIC;
```

### Create External AI Egress Restrictions

```sql
CREATE NETWORK RULE approved_ai_endpoints
  TYPE = HOST_PORT
  VALUE_LIST = (
    'api.openai.com:443',
    'api.anthropic.com:443'
  )
  MODE = EGRESS
  COMMENT = 'Approved external AI service endpoints';

CREATE EXTERNAL ACCESS INTEGRATION ai_egress_integration
  ALLOWED_NETWORK_RULES = ('approved_ai_endpoints')
  ALLOWED_AUTHENTICATION_SECRETS = ('openai_api_key', 'anthropic_api_key')
  ENABLED = TRUE
  COMMENT = 'Controlled egress to external AI services';
```

## Checklist

- [ ] Cortex roles follow least privilege (not blanket CORTEX_USER)
- [ ] CORTEX_EMBED_USER for embedding-only use cases
- [ ] CORTEX_ANALYST_USER for business analyst text-to-SQL
- [ ] CORTEX_AGENTS_USER for approved agentic workflows
- [ ] CORTEX_USER reserved for approved AI developers only
- [ ] External AI egress restricted to approved endpoints
- [ ] AI usage monitoring dashboards deployed
- [ ] Quarterly Cortex role access review scheduled
