---
name: moviepilot-cli
description: Use this skill when the user wants to find, download, or subscribe to a movie or TV show (including anime); asks about download or subscription status; needs to check or organize the media library; or mentions MoviePilot directly. Covers the full media acquisition workflow via MoviePilot — searching TMDB, filtering and downloading torrents from PT indexer sites, managing subscriptions for automatic episode tracking, and handling library organization, site accounts, filter rules, and schedulers.
---

# MoviePilot CLI

Use `scripts/mp-cli.js` to interact with the MoviePilot backend.

## Discover Commands

```bash
node scripts/mp-cli.js list           # list all available commands
node scripts/mp-cli.js show <command> # show parameters, required fields, and usage
```

Always run `show <command>` before calling a command. Do not guess parameter names or argument formats.

## Command Groups

| Category     | Commands                                                                                                                                                         |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Media Search | search_media, recognize_media, query_media_detail, get_recommendations, search_person, search_person_credits                                                     |
| Torrent      | search_torrents, get_search_results                                                                                                                              |
| Download     | add_download, query_download_tasks, delete_download, query_downloaders                                                                                           |
| Subscription | add_subscribe, query_subscribes, update_subscribe, delete_subscribe, search_subscribe, query_subscribe_history, query_popular_subscribes, query_subscribe_shares |
| Library      | query_library_exists, query_library_latest, transfer_file, scrape_metadata, query_transfer_history                                                               |
| Files        | list_directory, query_directory_settings                                                                                                                         |
| Sites        | query_sites, query_site_userdata, test_site, update_site, update_site_cookie                                                                                     |
| System       | query_schedulers, run_scheduler, query_workflows, run_workflow, query_rule_groups, query_episode_schedule, send_message                                          |

## Gotchas

- **Don't guess command parameters.** Parameter names vary per command and are not inferrable. Always run `show <command>` first.
- **`search_torrents` results are cached server-side.** `get_search_results` reads from that cache — always run `search_torrents` first in the same session before filtering.
- **Omitting `sites` uses the user's configured default sites**, not all available sites. Only call `query_sites` and pass `sites=` when the user explicitly asks for a specific site.
- **TMDB season numbers don't always match fan-labeled seasons.** Anime and long-running shows often split one TMDB season into parts. Always validate with `query_media_detail` when the user mentions a specific season.
- **`add_download` is irreversible without manual cleanup.** Always present torrent details and wait for explicit confirmation before calling it.
- **`volume_factor` and `freedate_diff` indicate promotional status.** `volume_factor` describes the discount type (e.g. `免费` = free download, `2X` = double upload only, `2X免费` = free download + double upload, `普通` = no discount). `freedate_diff` is the remaining free window (e.g. `2天3小时`); empty means no active promotion. Always include both fields when presenting results — they are critical for the user to pick the best-value torrent.

## Common Workflows

### Search and Download

```bash
# 1. Search TMDB to get tmdb_id
node scripts/mp-cli.js search_media title="流浪地球2" media_type="movie"

# [TV only, only if user specified a season] Validate season — see "Season Validation" section below
node scripts/mp-cli.js query_media_detail tmdb_id=... media_type="tv"

# 2. Search torrents using tmdb_id — results are cached server-side
#    Response includes available filter options (resolution, release group, etc.)
#    [Optional] If the user specifies sites, first run query_sites to get IDs, then pass them via sites param
node scripts/mp-cli.js query_sites                                                     # get site IDs
node scripts/mp-cli.js search_torrents tmdb_id=791373 media_type="movie"               # use user's default sites
node scripts/mp-cli.js search_torrents tmdb_id=791373 media_type="movie" sites='1,3'   # override with specific sites

# 3. Present available filter options to the user and ask for their preferences
#    e.g. "Available resolutions: 1080p, 2160p. Release groups: CMCT, PTer. Which do you prefer?"

# 4. Filter cached results using the user's selected preferences
node scripts/mp-cli.js get_search_results resolution='2160p'

# 5. Present ALL filtered results as a numbered list — do not pre-select or discard any
#    Show for each: index, title, size, seeders, resolution, release group, volume_factor, freedate_diff
#    Let the user pick by number; only then call add_download
node scripts/mp-cli.js add_download torrent_url="..."
```

### Add Subscription

```bash
# 1. Search to get tmdb_id (required for accurate identification)
node scripts/mp-cli.js search_media title="黑镜" media_type="tv"

# 2. Subscribe — the system will auto-download new episodes
node scripts/mp-cli.js add_subscribe title="黑镜" year="2011" media_type="tv" tmdb_id=42009
```

### Manage Subscriptions

```bash
node scripts/mp-cli.js query_subscribes status=R                                   # list active
node scripts/mp-cli.js update_subscribe subscribe_id=123 resolution="1080p"        # update filters
node scripts/mp-cli.js search_subscribe subscribe_id=123                           # search missing episodes
node scripts/mp-cli.js delete_subscribe subscribe_id=123                           # remove
```

## Season Validation (only when user specifies a season)

Skip this section if the user did not mention a specific season.

**Step 1 — Verify the season exists:**

```bash
node scripts/mp-cli.js query_media_detail tmdb_id=<id> media_type="tv"
```

Check `season_info` against the season the user requested:

- **Season exists:** use that season number directly, then proceed to torrent search.
- **Season does not exist:** anime and long-running shows often split one TMDB season into multiple parts that fans call separate seasons. Use the latest available season number and continue to Step 2.

**Step 2 — Identify the correct episode range:**

```bash
node scripts/mp-cli.js query_episode_schedule tmdb_id=<id> season=<latest_season>
```

Use `air_date` to find a block of recently-aired episodes that likely corresponds to what the user calls the missing season. If no such block exists, tell the user the content is unavailable. Otherwise, confirm the episode range with the user before proceeding to torrent search.

## Error Handling

| Error                 | Resolution                                                                                                                                                                                                  |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No search results     | Retry with an alternative title (e.g. English title). If still empty, ask the user to confirm the title or provide the TMDB ID directly.                                                                    |
| Download failure      | Check downloader status with `query_downloaders`; advise the user to verify storage or downloader health. If these are normal, mention it could be a network error and suggest retrying later.              |
| Missing configuration | Ask the user for the backend host and API key. Once provided, run `node scripts/mp-cli.js -h <HOST> -k <KEY>` (no command) to save the config persistently — subsequent commands will use it automatically. |
