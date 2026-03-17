---
name: exfiltration-detection
description: "Detect data exfiltration attempts in Snowflake. Use when: investigating bulk data exports, suspicious UNLOAD/COPY activity, external stage transfers, GET commands, presigned URL generation, unusual stage creation, or data sharing activity. Triggers: exfiltration, data theft, bulk export, UNLOAD, COPY INTO, GET command, presigned URL, external stage, data leak, data sharing, CREATE SHARE, listing, marketplace."
---

# Exfiltration Detection

Analyze Snowflake activity for potential data exfiltration patterns.

## Workflow

### Step 1: Select Detection Scope

**Ask user:**
```
What timeframe should I analyze?
1. Last 24 hours
2. Last 7 days
3. Last 30 days
4. Custom date range
```

**⚠️ STOP**: Wait for user response.

### Step 2: Run Detection Queries

Execute these queries against `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY` to identify exfiltration indicators:

#### 2a: UNLOAD Operations (Data Export to Stages/External Locations)

```sql
SELECT
    query_id,
    user_name,
    role_name,
    query_type,
    query_text,
    rows_produced,
    bytes_scanned,
    start_time,
    end_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'UNLOAD'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY bytes_scanned DESC
LIMIT 100;
```

#### 2b: COPY INTO with External URLs or User Stages

```sql
SELECT
    query_id,
    user_name,
    role_name,
    query_text,
    rows_produced,
    bytes_scanned,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'COPY'
  AND (
    LOWER(query_text) LIKE '%s3://%'
    OR LOWER(query_text) LIKE '%azure://%'
    OR LOWER(query_text) LIKE '%gcs://%'
    OR LOWER(query_text) LIKE '%@~%'
  )
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY bytes_scanned DESC
LIMIT 100;
```

#### 2c: GET Commands (Download from Stages)

```sql
SELECT
    query_id,
    user_name,
    role_name,
    query_text,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'GET_FILES'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC
LIMIT 100;
```

#### 2d: GET_PRESIGNED_URL Function Calls

```sql
SELECT
    query_id,
    user_name,
    role_name,
    query_text,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE LOWER(query_text) LIKE '%get_presigned_url%'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC
LIMIT 100;
```

#### 2e: Stage Creation Events

```sql
SELECT
    query_id,
    user_name,
    role_name,
    query_text,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type = 'CREATE_STAGE'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC
LIMIT 100;
```

#### 2f: COPY FILES Commands

```sql
SELECT
    query_id,
    user_name,
    role_name,
    query_text,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE LOWER(query_text) LIKE '%copy files%'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC
LIMIT 100;
```

#### 2g: Data Sharing - CREATE/ALTER SHARE

```sql
SELECT
    query_id,
    user_name,
    role_name,
    query_type,
    query_text,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type IN ('CREATE_SHARE', 'ALTER_SHARE')
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC
LIMIT 100;
```

#### 2h: Data Sharing - Listing Activity

```sql
SELECT
    query_id,
    user_name,
    role_name,
    query_type,
    query_text,
    start_time,
    execution_status
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_type LIKE '%LISTING%'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
ORDER BY start_time DESC
LIMIT 100;
```

#### 2i: Active Shares and Their Contents

```sql
SELECT
    share_name,
    database_name,
    created_on,
    owner,
    comment
FROM SNOWFLAKE.ACCOUNT_USAGE.SHARES
WHERE deleted IS NULL
ORDER BY created_on DESC;
```

#### 2j: Share Grants to External Accounts

```sql
SELECT
    share_name,
    granted_to,
    grantee_name,
    created_on
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_SHARES
WHERE deleted_on IS NULL
ORDER BY created_on DESC
LIMIT 100;
```

#### 2k: Large Result Set Downloads (UI Exfiltration)

```sql
SELECT
    query_id,
    user_name,
    role_name,
    LEFT(query_text, 150) as query_preview,
    rows_produced,
    bytes_scanned,
    start_time
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE rows_produced > 10000
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
  AND execution_status = 'SUCCESS'
  AND query_type = 'SELECT'
  AND user_name != 'SYSTEM'
ORDER BY rows_produced DESC
LIMIT 100;
```

#### 2l: RESULT_SCAN Usage (Indicates Result Re-download)

```sql
SELECT
    query_id,
    user_name,
    role_name,
    query_text,
    rows_produced,
    start_time
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE LOWER(query_text) LIKE '%result_scan%'
  AND start_time >= DATEADD('day', -{{DAYS}}, CURRENT_TIMESTAMP())
  AND user_name != 'SYSTEM'
ORDER BY rows_produced DESC
LIMIT 100;
```

### Step 3: Analyze Results

For each finding, evaluate:

| Risk Factor | High Risk Indicator |
|-------------|---------------------|
| Volume | Bytes scanned > 1GB or rows > 1M |
| Destination | External cloud URLs (s3://, azure://, gcs://) |
| User stage | @~ prefix (user's personal stage) |
| Timing | Outside business hours or weekends |
| User | Service accounts or inactive users |
| Frequency | Multiple exports in short timeframe |
| Sharing | New shares to unknown accounts |
| Sharing | Shares with broad object grants |
| Listing | New marketplace listings |
| UI Download | Large result sets (>10K rows) from SELECT |
| UI Download | RESULT_SCAN usage to re-fetch results |

### Step 4: Present Findings

**⚠️ MANDATORY CHECKPOINT**: Present summary before recommendations.

Format results as:

```
## Exfiltration Detection Summary

**Timeframe**: [date range]
**Total suspicious events**: [count]

### High-Risk Findings
[List events with high-risk indicators]

### Medium-Risk Findings
[List events with some risk indicators]

### Users with Multiple Export Events
[Aggregate by user_name]
```

### Step 5: Recommend Actions

Based on findings, suggest:
- Users to investigate further
- Stages to audit or remove
- Network policies to implement
- Access grants to revoke
- Shares to review or drop
- Listings to unpublish

**⚠️ STOP**: Wait for user to decide on next steps.

## Stopping Points

- ✋ Step 1: After scope selection
- ✋ Step 4: After presenting findings
- ✋ Step 5: After recommendations

## Output

Summary report of potential exfiltration activity with risk-ranked findings and remediation recommendations.
