---
name: database-operation
description: >-
  Use this skill when you need to execute SQL against the MoviePilot database.
  This skill guides you through connecting to the database and executing SQL statements.
  The database type (SQLite or PostgreSQL) and connection details are provided in the system prompt <system_info>.
  Applicable scenarios include:
  1) The user asks about data statistics, counts, or aggregations that existing tools don't cover;
  2) The user wants to inspect, modify, or fix raw database records;
  3) The user asks to clean up data, update records, or perform database maintenance;
  4) The user asks questions like "how many downloads", "show me site stats", "delete old records", etc.
allowed-tools: execute_command read_file
---

# Database Query (数据库查询)

This skill guides you through executing SQL against the MoviePilot database. Both read and write operations are supported.

## Prerequisites

You need the following tools:
- `execute_command` - Execute shell commands to run database queries

## Getting Database Connection Info

The system prompt `<system_info>` section already contains all the database connection details you need:
- **数据库类型** — `sqlite` or `postgresql`
- **数据库** — Full connection info:
  - For SQLite: the database file path, e.g. `SQLite (/config/db/moviepilot.db)`
  - For PostgreSQL: the connection string, e.g. `PostgreSQL (user:password@host:port/database)`

**Do NOT run any detection commands.** Extract the database type and connection details directly from `<system_info>`.

## Executing Queries

### SQLite Mode

Extract the database file path from `<system_info>` (the path inside the parentheses after `SQLite`).

Use `execute_command` to run queries:

```bash
sqlite3 -header -column <DB_PATH> "YOUR SQL QUERY HERE;"
```

For JSON-formatted output (easier to parse):

```bash
sqlite3 -json <DB_PATH> "YOUR SQL QUERY HERE;"
```

**List all tables:**

```bash
sqlite3 -header -column <DB_PATH> "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
```

**View table schema:**

```bash
sqlite3 <DB_PATH> ".schema tablename"
```

### PostgreSQL Mode

Extract the connection parameters from `<system_info>` (parse `user:password@host:port/database` from the parentheses after `PostgreSQL`).

Use `execute_command` to run queries via `psql`:

```bash
PGPASSWORD=<password> psql -h <host> -p <port> -U <user> -d <database> -c "YOUR SQL QUERY HERE;"
```

**List all tables:**

```bash
PGPASSWORD=<password> psql -h <host> -p <port> -U <user> -d <database> -c "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;"
```

**View table schema:**

```bash
PGPASSWORD=<password> psql -h <host> -p <port> -U <user> -d <database> -c "\d tablename"
```

## Interpret Results

After executing the query, analyze the results and present them in a clear, user-friendly format. Use aggregation, sorting, and filtering as needed.

## Database Schema Reference

MoviePilot uses the following core tables:

### downloadhistory (下载历史)
Key columns: `id`, `path`, `type`, `title`, `year`, `tmdbid`, `imdbid`, `doubanid`, `seasons`, `episodes`, `downloader`, `download_hash`, `torrent_name`, `torrent_site`, `userid`, `username`, `date`, `media_category`

### downloadfiles (下载文件)
Key columns: `id`, `downloader`, `download_hash`, `fullpath`, `savepath`, `filepath`, `torrentname`, `state`

### transferhistory (整理历史)
Key columns: `id`, `src`, `dest`, `mode`, `type`, `category`, `title`, `year`, `tmdbid`, `seasons`, `episodes`, `download_hash`, `status` (boolean: true=success, false=failed), `errmsg`, `date`

### subscribe (订阅)
Key columns: `id`, `name`, `year`, `type`, `tmdbid`, `doubanid`, `season`, `total_episode`, `start_episode`, `lack_episode`, `state` ('N'=new, 'R'=running, 'S'=paused), `filter`, `include`, `exclude`, `quality`, `resolution`, `sites`, `best_version`, `date`, `username`

### subscribehistory (订阅历史)
Key columns: `id`, `name`, `year`, `type`, `tmdbid`, `doubanid`, `season`, `total_episode`, `start_episode`, `date`, `username`

### user (用户)
Key columns: `id`, `name`, `email`, `is_active`, `is_superuser`, `permissions`, `settings`

### site (站点)
Key columns: `id`, `name`, `domain`, `url`, `pri` (priority), `cookie`, `proxy`, `is_active`, `downloader`, `limit_interval`, `limit_count`

### siteuserdata (站点用户数据)
Key columns: `id`, `domain`, `name`, `username`, `user_level`, `bonus`, `upload`, `download`, `ratio`, `seeding`, `leeching`, `seeding_size`, `updated_day`

### sitestatistic (站点统计)
Key columns: `id`, `domain`, `success`, `fail`, `seconds`, `lst_state`, `lst_mod_date`

### mediaserveritem (媒体库条目)
Key columns: `id`, `server`, `library`, `item_id`, `item_type`, `title`, `original_title`, `year`, `tmdbid`, `imdbid`, `tvdbid`, `path`

### systemconfig (系统配置)
Key columns: `id`, `key`, `value` (JSON)

### userconfig (用户配置)
Key columns: `id`, `username`, `key`, `value` (JSON)

### plugindata (插件数据)
Key columns: `id`, `plugin_id`, `key`, `value` (JSON)

### message (消息)
Key columns: `id`, `channel`, `source`, `mtype`, `title`, `text`, `image`, `link`, `userid`, `reg_time`

### workflow (工作流)
Key columns: `id`, `name`, `description`, `timer`, `trigger_type`, `event_type`, `state` ('W'=waiting, 'R'=running), `run_count`, `actions`, `flows`, `last_time`

### passkey (通行密钥)
Key columns: `id`, `user_id`, `credential_id`, `public_key`, `name`, `created_at`, `last_used_at`, `is_active`

### siteicon (站点图标)
Key columns: `id`, `name`, `domain`, `url`, `base64`

## Common Query Examples

### Count total downloads
```sql
SELECT COUNT(*) AS total FROM downloadhistory;
```

### Recent download history
```sql
SELECT title, year, type, torrent_site, date FROM downloadhistory ORDER BY id DESC LIMIT 10;
```

### Failed transfers
```sql
SELECT id, title, src, errmsg, date FROM transferhistory WHERE status = 0 ORDER BY id DESC LIMIT 10;
```

### Active subscriptions
```sql
SELECT name, year, type, season, state, lack_episode FROM subscribe WHERE state = 'R';
```

### Site upload/download statistics
```sql
SELECT name, domain, upload, download, ratio, bonus, seeding, user_level FROM siteuserdata ORDER BY upload DESC;
```

### Media library statistics
```sql
SELECT server, library, COUNT(*) AS count FROM mediaserveritem GROUP BY server, library;
```

### Site access success rate
```sql
SELECT domain, success, fail, ROUND(success * 100.0 / (success + fail), 1) AS success_rate FROM sitestatistic WHERE success + fail > 0 ORDER BY success_rate DESC;
```

### Plugin data inspection
```sql
SELECT plugin_id, key FROM plugindata ORDER BY plugin_id, key;
```

### Delete old download history (write operation)
```sql
DELETE FROM downloadhistory WHERE date < '2024-01-01';
```

### Update subscription state (write operation)
```sql
UPDATE subscribe SET state = 'S' WHERE id = 123;
```

### Clean up failed transfer records (write operation)
```sql
DELETE FROM transferhistory WHERE status = 0 AND date < '2024-06-01';
```

## Safety Rules

1. **Confirm before writing** — For any `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, or `TRUNCATE` operation, always describe what the statement will do and ask the user to confirm before executing. For `SELECT` queries, execute directly without confirmation
2. **Back up before destructive operations** — Before executing `DELETE`, `DROP`, or `TRUNCATE` on important tables, suggest the user back up the data first (e.g., export with `.dump` for SQLite or `pg_dump` for PostgreSQL)
3. **Use WHERE clauses** — Never run `UPDATE` or `DELETE` without a `WHERE` clause unless the user explicitly intends to affect all rows
4. **Use LIMIT for queries** — When querying large tables with `SELECT`, add `LIMIT` to prevent excessive output
5. **Sensitive data** — The `site` table contains `cookie`, `apikey`, and `token` fields. NEVER display these values to the user. Exclude them from SELECT or replace with `'***'`
6. **Password data** — The `user` table contains `hashed_password` and `otp_secret` fields. NEVER display these values
7. **Output limits** — If the query results are very long, summarize or truncate them

## SQL Dialect Differences

When writing queries, be aware of differences between SQLite and PostgreSQL:

| Feature | SQLite | PostgreSQL |
|---------|--------|------------|
| Boolean values | `0` / `1` | `false` / `true` |
| String concat | `\|\|` | `\|\|` or `CONCAT()` |
| Current time | `datetime('now')` | `NOW()` |
| LIMIT syntax | `LIMIT n` | `LIMIT n` |
| JSON access | `json_extract(col, '$.key')` | `col->>'key'` |
| Case sensitivity | Case-insensitive by default | Case-sensitive |
| LIKE | Case-insensitive | Use `ILIKE` for case-insensitive |

## Troubleshooting

- **sqlite3 not found**: The `sqlite3` CLI should be pre-installed in the MoviePilot Docker container. If missing, you can try using Python: `python3 -c "import sqlite3; ..."`
- **psql not found**: For PostgreSQL, if `psql` is not available, use Python: `python3 -c "import psycopg2; ..."`
- **Permission denied**: Database queries require admin privileges
- **Table not found**: Use the "list all tables" query first to verify table names
