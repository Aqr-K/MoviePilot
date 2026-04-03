---
name: transfer-failed-retry
description: Use this skill when you need to retry a failed file transfer/organization. Given a failed transfer history record ID, this skill guides you through querying the failure details, deleting the old record, and re-identifying and re-organizing the file. This skill is automatically triggered when the system detects a transfer failure and the AI agent retry feature is enabled.
allowed-tools: query_transfer_history delete_transfer_history recognize_media transfer_file search_media
---

# Transfer Failed Retry (整理失败重试)

This skill handles retrying failed file transfers/organizations. When a file transfer fails, you can use this skill to analyze the failure, remove the stale history record, and attempt to re-identify and re-organize the file.

## Prerequisites

You need the following tools:
- `query_transfer_history` - Query transfer history records
- `delete_transfer_history` - Delete a transfer history record
- `recognize_media` - Recognize media info from file path or title
- `transfer_file` - Transfer/organize files to the media library
- `search_media` - Search TMDB for media information

## Workflow

### Step 1: Query the Failed Transfer History

Use `query_transfer_history` to get details about the failed record. Filter by status `failed` to find the specific record.

If you are given a specific history record ID, query with that ID to understand the failure context:

```
query_transfer_history(status="failed")
```

From the record, extract the following key information:
- **id**: The history record ID
- **src**: Source file path
- **title**: The recognized title (may be incorrect)
- **errmsg**: The error message explaining why the transfer failed
- **type**: Media type (movie/tv)
- **tmdbid**: TMDB ID (if available)
- **seasons/episodes**: Season/episode info (if TV show)
- **downloader**: Which downloader was used
- **download_hash**: The torrent hash

### Step 2: Analyze the Failure Reason

Common failure reasons and how to handle them:

| Error Message | Cause | Solution |
|---------------|-------|----------|
| 未识别到媒体信息 | File name couldn't be matched to any media | Use `search_media` to find the correct TMDB ID, then use `transfer_file` with explicit `tmdbid` |
| 源目录不存在 | Source file was moved or deleted | Cannot retry - skip this record |
| 目标路径不存在 | Target directory issue | Retry transfer - the directory config may have been fixed |
| 文件已存在 | Target file already exists | May need to use `force` mode or skip |
| 未找到有效的集数信息 | Episode number not recognized | Use `recognize_media` with the file path to get better metadata, or specify season/episode in `transfer_file` |
| 未获取到转移目录设置 | No transfer directory configured for this media type | Cannot auto-fix - notify user about directory configuration |

### Step 3: Delete the Failed History Record

Before retrying, you **must** delete the old failed history record. The system skips files that already have a transfer history entry (even failed ones).

```
delete_transfer_history(history_id=<record_id>)
```

### Step 4: Re-identify and Re-organize

Based on the failure analysis in Step 2:

#### Case A: Unrecognized Media (未识别到媒体信息)

1. Try recognizing the media from file path:
   ```
   recognize_media(path="<source_file_path>")
   ```

2. If recognition fails, try searching TMDB with keywords extracted from the filename:
   ```
   search_media(title="<extracted_title>", media_type="movie" or "tv")
   ```

3. Once you have the correct TMDB ID, re-transfer with explicit identification:
   ```
   transfer_file(file_path="<source_path>", tmdbid=<tmdb_id>, media_type="movie" or "tv")
   ```

#### Case B: Transfer Error (file operation failed)

Simply retry the transfer:
```
transfer_file(file_path="<source_path>")
```

#### Case C: Episode Recognition Issue

For TV shows where episode info couldn't be determined:
1. Use `recognize_media` to get better metadata
2. Re-transfer with explicit season info:
   ```
   transfer_file(file_path="<source_path>", tmdbid=<tmdb_id>, media_type="tv", season=<season_number>)
   ```

### Step 5: Report Result

After the retry attempt, report the result:
- If successful: Confirm the file has been organized correctly
- If failed again: Report the new error and suggest manual intervention

## Important Notes

- **Always delete the old history record first** before retrying. The system will skip files with existing history.
- **Do not retry** if the source file no longer exists (源目录不存在).
- **Do not retry** if the error is about missing directory configuration - this requires user intervention.
- **For unrecognized media**, always try `recognize_media` with the file path first before falling back to `search_media`.
- **Be cautious with TV shows** - ensure the correct season and episode information is used.
- When this skill is triggered automatically by the system, it provides the `history_id` directly. Start from Step 1 with that specific ID.

## Example: Complete Retry Flow

```
# 1. Query the failed record
query_transfer_history(status="failed", page=1)
# Found: id=42, src="/downloads/Movie.Name.2024.1080p.mkv", errmsg="未识别到媒体信息"

# 2. Try to recognize the media from path
recognize_media(path="/downloads/Movie.Name.2024.1080p.mkv")
# Recognition failed

# 3. Search TMDB
search_media(title="Movie Name", year="2024", media_type="movie")
# Found: tmdb_id=123456

# 4. Delete old history record
delete_transfer_history(history_id=42)

# 5. Re-transfer with correct identification
transfer_file(file_path="/downloads/Movie.Name.2024.1080p.mkv", tmdbid=123456, media_type="movie")
# Success!
```
