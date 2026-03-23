---
name: moviepilot-cli
description: Use this skill for any request involving movies, TV shows, or anime, including searching, downloads, subscriptions, library management. Also use this skill whenever the user explicitly mentions MoviePilot.
---

# MoviePilot CLI

> All script paths are relative to this skill file.

Use `scripts/mp-cli.js` to interact with the MoviePilot backend.

## Discover Commands

List all available commands: `node scripts/mp-cli.js list`

Show parameters and usage for a specific command: `node scripts/mp-cli.js show <command>`

Always run `show <command>` before calling a command — parameter names are not inferable, do not guess.

## Command Groups

| Category | Commands |
|---|---|
| Media Search | search_media, recognize_media, query_media_detail, get_recommendations, search_person, search_person_credits |
| Torrent | search_torrents, get_search_results |
| Download | add_download, query_download_tasks, delete_download, query_downloaders |
| Subscription | add_subscribe, query_subscribes, update_subscribe, delete_subscribe, search_subscribe, query_subscribe_history, query_popular_subscribes, query_subscribe_shares |
| Library | query_library_exists, query_library_latest, transfer_file, scrape_metadata, query_transfer_history |
| Files | list_directory, query_directory_settings |
| Sites | query_sites, query_site_userdata, test_site, update_site, update_site_cookie |
| System | query_schedulers, run_scheduler, query_workflows, run_workflow, query_rule_groups, query_episode_schedule, send_message |

## Workflows

### Search and Download

#### 1. Search TMDB

Search for a movie or TV show by title: 
`node scripts/mp-cli.js search_media title="..." media_type="movie"`

If the user specifies a TV season, run Season Validation step first — the season number provided by the user may not match TMDB.

#### 2. Search torrents

Prefer `tmdb_id`; use `douban_id` only when `tmdb_id` is unavailable.

Omitting `sites=` uses the user's default sites. If the user specifies sites, first retrieve site IDs:
`node scripts/mp-cli.js query_sites`

Search torrents using default sites:
`node scripts/mp-cli.js search_torrents tmdb_id=791373 media_type="movie"`

Search torrents using user-specified sites (pass site IDs from `query_sites`):
`node scripts/mp-cli.js search_torrents tmdb_id=791373 media_type="movie" sites='1,3'`

When `search_torrents` returns:
1. **Stop** — do not call `get_search_results` yet.
2. Present all `filter_options` fields and every value within each field to the user verbatim.
3. Do not pre-select, summarize, or omit any field or value.
4. Wait for the user to select filters or confirm no filters are needed before moving to the next step.

#### 3. Get filtered results (only after user has responded to filter_options)

Run `node scripts/mp-cli.js show get_search_results` to check available parameters. Filter logic: OR within a field, AND across fields.

Filter values must come from the `filter_options` returned by `search_torrents` — do not invent, translate, normalize, or use values from any other source. Note: `filter_options` keys are camelCase (e.g., `freeState`), but `get_search_results` params are snake_case (e.g., `free_state`).

Fetch results with selected filters:
`node scripts/mp-cli.js get_search_results resolution='1080p,2160p' free_state='免费,50%'`

If empty, tell the user which filter to relax and ask before retrying.

#### 4. Present results as a numbered list

Show all results without pre-selection. Each row: index, title, size, seeders, resolution, release group, `volume_factor`, `freedate_diff`.

| `volume_factor` | Meaning |
|---|---|
| `免费` | Free download |
| `50%` | 50% download size |
| `2X` | Double upload |
| `2X免费` | Double upload + free |
| `普通` | No discount |

`freedate_diff`: remaining free window (e.g., `2天3小时`).

#### 5. Check before downloading

After the user picks torrents: Run **Check Library and Subscriptions** step.

If the media already exists in the library or is already subscribed, **stop** and report the finding to the user.

#### 6. Add download

Download one or more torrents (`torrent_url` comes from `get_search_results` output):
`node scripts/mp-cli.js add_download torrent_url="abc1234:1,def5678:2"`

#### Error handling

| Step | Action |
|---|---|
| `search_media` empty | Retry with alternative title (English/original), inform user. Still empty → ask for title or TMDB ID. |
| `search_torrents` empty | Inform user, ask whether to retry with different sites. |
| `get_search_results` empty | Do not silently broaden filters. Suggest which filter to relax, ask before retrying. |
| `add_download` fails | Run `query_downloaders` + `query_download_tasks` to diagnose, then report to user. |

### Add Subscription

1. Search for the media to get `tmdb_id`: Run `search_media`.
2. Run **Check Library and Subscriptions** step, if media already exists or is subscribed, **stop** and report to user.
3. If the user specifies a TV season, run Season Validation step first.

Subscribe to a movie or TV show:
`node scripts/mp-cli.js add_subscribe title="..." year="2011" media_type="tv" tmdb_id=42009`

Subscribe to a specific season:
`node scripts/mp-cli.js add_subscribe title="..." year="2011" media_type="tv" tmdb_id=42009 season=4`

Subscribe starting from a specific episode:
`node scripts/mp-cli.js add_subscribe title="..." year="2024" media_type="tv" tmdb_id=12345 season=1 start_episode=13`

### Manage Downloads

List download tasks and get hash for further operations:
`node scripts/mp-cli.js query_download_tasks status=downloading`

Delete a download task (confirm with user first — irreversible):
`node scripts/mp-cli.js delete_download hash=<hash>`

Delete a download task and also remove its files (confirm with user first — irreversible):
`node scripts/mp-cli.js delete_download hash=<hash> delete_files=true`

### Manage Subscriptions

List active subscriptions:
`node scripts/mp-cli.js query_subscribes status=R`

Update subscription filters:
`node scripts/mp-cli.js update_subscribe subscribe_id=123 resolution="1080p"`

Trigger a search for missing episodes (confirm with user first):
`node scripts/mp-cli.js search_subscribe subscribe_id=123`

Remove a subscription (confirm with user first):
`node scripts/mp-cli.js delete_subscribe subscribe_id=123`

### Check Library and Subscriptions

Run before any download or subscription to avoid duplicates.

Check if the media already exists in the library:
`node scripts/mp-cli.js query_library_exists tmdb_id=123456 media_type="movie"`

Check if the media is already subscribed:
`node scripts/mp-cli.js query_subscribes tmdb_id=123456`

### Season Validation

Mandatory when user specifies a season. Productions sometimes release a show in multiple parts under one TMDB season; online communities and torrent sites may label each part as a separate "season".

#### 1. Verify season exists

Fetch media detail to check available seasons:
`node scripts/mp-cli.js query_media_detail tmdb_id=<id> media_type="tv"`

Compare `season_info` with the user's requested season:
1. If the season exists in `season_info` → use that season number directly and return to the calling workflow.
2. If the season does not exist → the user's "season" likely maps to a later episode range within an existing TMDB season. Note the latest (highest-numbered) season from `season_info`, then continue to next step.

#### 2. Identify the correct episode range

Fetch episode schedule for the latest season from `season_info`:
`node scripts/mp-cli.js query_episode_schedule tmdb_id=<id> season=<latest_season_number>`

Use `air_date` to find a block of recently-aired episodes that likely corresponds to what the user calls the missing season. Look for a gap in `air_date` between episodes — the gap indicates a part break, and the episodes after the gap are what the user likely refers to as the next "season". For example, if TMDB Season 1 has episodes 1–24 and there is a multi-month gap between episode 12 and 13, then episodes 13–24 correspond to the user's "Season 2". If no such gap exists, tell user content is unavailable. Otherwise confirm the episode range with user.

## Error handling

Missing configuration: Ask the user for the backend host and API key. Once provided, save the config persistently — subsequent commands will use it automatically:
`node scripts/mp-cli.js -h <HOST> -k <KEY>`
