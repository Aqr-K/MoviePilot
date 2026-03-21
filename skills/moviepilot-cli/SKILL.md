---
name: moviepilot-cli
description: Use this skill when the user wants to find, download, or subscribe to a movie or TV show (including anime); asks about download or subscription status; needs to check or organize the media library; or mentions MoviePilot directly. Covers the full media acquisition workflow via MoviePilot — searching TMDB, filtering and downloading torrents from indexer sites, managing subscriptions for automatic episode tracking, and handling library organization, site accounts, filter rules, and schedulers.
---

# MoviePilot CLI

> **Path note:** All script paths in this skill are relative to this skill file.

Use `scripts/mp-cli.js` to interact with the MoviePilot backend.

## Discover Commands

```bash
node scripts/mp-cli.js list           # list all available commands
node scripts/mp-cli.js show <command> # show parameters, required fields, and usage
```

Always run `show <command>` before calling a command. Parameter names vary per command and are not inferable — do not guess.

## Command Groups

**Media Search:** search_media, recognize_media, query_media_detail, get_recommendations, search_person, search_person_credits
**Torrent:** search_torrents, get_search_results
**Download:** add_download, query_download_tasks, delete_download, query_downloaders
**Subscription:** add_subscribe, query_subscribes, update_subscribe, delete_subscribe, search_subscribe, query_subscribe_history, query_popular_subscribes, query_subscribe_shares
**Library:** query_library_exists, query_library_latest, transfer_file, scrape_metadata, query_transfer_history
**Files:** list_directory, query_directory_settings
**Sites:** query_sites, query_site_userdata, test_site, update_site, update_site_cookie
**System:** query_schedulers, run_scheduler, query_workflows, run_workflow, query_rule_groups, query_episode_schedule, send_message

## Common Workflows

### Search and Download

```bash
# 1. Search TMDB to get tmdb_id
node scripts/mp-cli.js search_media title="流浪地球2" media_type="movie"

# [TV only, only if user specified a season] the user's season may not match TMDB; validate first, see "Season Validation" section below
node scripts/mp-cli.js query_media_detail tmdb_id=... media_type="tv"

# 2. Search torrents — results are cached server-side; get_search_results reads from this cache
#    Omitting sites= uses the user's configured default sites; only pass it when explicitly requested
node scripts/mp-cli.js query_sites                                                     # get site IDs (only if needed)
node scripts/mp-cli.js search_torrents tmdb_id=791373 media_type="movie"               # default sites
node scripts/mp-cli.js search_torrents tmdb_id=791373 media_type="movie" sites='1,3'   # specific sites

# 3. Present the filter_options from step 2's response to the user and ask which ones to apply
#    Show every field and its values — do not pre-select or omit any
#    e.g. "分辨率: 1080p, 2160p；字幕组: CMCT, PTer；请问需要筛选哪些条件？"

# [Optional] If you need to review the available filter_options again without re-running search_torrents
node scripts/mp-cli.js get_search_results show_filter_options=true

# 4. Filter cached results based on user preferences and your own judgment
#    Each param is an array (OR within a field, AND across fields): resolution='1080p,2160p' free_state='免费,50%'
#    IMPORTANT: filter_options keys are camelCase (freeState) but params are snake_case (free_state)
#    If results come back empty, drop the most restrictive field and retry
node scripts/mp-cli.js get_search_results resolution='2160p'
node scripts/mp-cli.js get_search_results resolution='1080p,2160p' free_state='免费,50%'

# 5. Present ALL filtered results as a numbered list — do not pre-select or discard any
#    Show for each: index, title, size, seeders, resolution, release group, volume_factor, freedate_diff
#    volume_factor: 免费=free download, 50%=download counted at 50% size, 2X=double upload, 2X免费=both, 普通=no discount
#    freedate_diff: remaining free window (e.g. "2天3小时"); empty = no active promotion
#    Let the user pick by number; only then proceed to step 6

# 6. After user confirms selection, check library and subscriptions before downloading
node scripts/mp-cli.js query_library_exists tmdb_id=123456 media_type="movie"  # or "tv"
node scripts/mp-cli.js query_subscribes tmdb_id=123456
# If already in library or subscribed, warn the user and ask for confirmation to proceed

# 7. Add download — this is irreversible without manual cleanup, always confirm with user first
node scripts/mp-cli.js add_download torrent_url="abc1234:1"                       # single
node scripts/mp-cli.js add_download torrent_url="abc1234:1,def5678:2"             # multiple
```

### Add Subscription

```bash
# 1. Search to get tmdb_id (required for accurate identification)
node scripts/mp-cli.js search_media title="黑镜" media_type="tv"

# 2. Check library and existing subscriptions (same as Search and Download step 6)

# 3. Subscribe — the system will auto-download new episodes
#    If the user specified a season, run Season Validation first to get the correct season + start_episode
#    Pass start_episode= when the user's requested season maps to a mid-season episode range on TMDB
#    (e.g. fans call it "Season 2" but TMDB only has Season 1, episodes starting from ep 13)
node scripts/mp-cli.js add_subscribe title="黑镜" year="2011" media_type="tv" tmdb_id=42009
node scripts/mp-cli.js add_subscribe title="黑镜" year="2011" media_type="tv" tmdb_id=42009 season=4  # specific season
node scripts/mp-cli.js add_subscribe title="某动漫" year="2024" media_type="tv" tmdb_id=12345 season=1 start_episode=13  # mid-season start
```

### Manage Subscriptions

```bash
node scripts/mp-cli.js query_subscribes status=R                                   # list active
node scripts/mp-cli.js update_subscribe subscribe_id=123 resolution="1080p"        # update filters
node scripts/mp-cli.js search_subscribe subscribe_id=123                           # search missing episodes
node scripts/mp-cli.js delete_subscribe subscribe_id=123                           # remove
```

## Season Validation (only when user specifies a season)

Productions sometimes release a show in multiple cours under one season; online communities and torrent sites may label each cour as a separate season.

**Step 1 — Verify the season exists:**

```bash
node scripts/mp-cli.js query_media_detail tmdb_id=<id> media_type="tv"
```

Check `season_info` against the season the user requested:

- **Season exists:** use that season number directly, then proceed to torrent search.
- **Season does not exist:** use the latest available season number and continue to Step 2.

**Step 2 — Identify the correct episode range:**

```bash
node scripts/mp-cli.js query_episode_schedule tmdb_id=<id> season=<latest_season>
```

Use `air_date` to find a block of recently-aired episodes that likely corresponds to what the user calls the missing season. If no such block exists, tell the user the content is unavailable. Otherwise, confirm the episode range with the user, then use the `season=` filter in `get_search_results` to narrow torrent results to that range (e.g. `season='S01 E13,S01 E14'`).

## Error Handling

**No search results:** Retry with an alternative title (e.g. English title). If still empty, ask the user to confirm the title or provide the TMDB ID directly.

**Download failure:** Run `query_downloaders` to check downloader health, then `query_download_tasks` to check if the task already exists (duplicate tasks are rejected). If both are normal, report findings to the user and mention it may be a network error — suggest retrying later.

**Missing configuration:** Ask the user for the backend host and API key. Once provided, run `node scripts/mp-cli.js -h <HOST> -k <KEY>` (no command) to save the config persistently — subsequent commands will use it automatically.
