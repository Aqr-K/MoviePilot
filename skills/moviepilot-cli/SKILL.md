---
name: moviepilot-cli
description: Use this skill for any request involving movies, TV shows, or anime, including searching, downloads, subscriptions, library management. Also use this skill whenever the user explicitly mentions MoviePilot.
---

# MoviePilot CLI

> All script paths are relative to this skill file.

Use `scripts/mp-cli.js` to interact with the MoviePilot backend.

## Discover Commands

```bash
node scripts/mp-cli.js list           # list all available commands
node scripts/mp-cli.js show <command> # show parameters and usage
```

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

```bash
node scripts/mp-cli.js search_media title="..." media_type="movie"
```

For TV with user-specified season: the user's season may not match TMDB — run Season Validation (see below).

```bash
node scripts/mp-cli.js query_media_detail tmdb_id=... media_type="tv"
```

#### 2. Search torrents

Prefer `tmdb_id`; use `douban_id` only when `tmdb_id` is unavailable.
Omitting `sites=` uses the user's default sites. If the user specifies sites, run `query_sites` first to get site IDs, then pass them via `sites=` to `search_torrents` — do not skip this step.

```bash
node scripts/mp-cli.js query_sites                                                    # get site IDs
node scripts/mp-cli.js search_torrents tmdb_id=791373 media_type="movie"              # default sites
node scripts/mp-cli.js search_torrents tmdb_id=791373 media_type="movie" sites='1,3'  # user-specified sites
```

After `search_torrents` returns, you must stop and present **all** `filter_options` fields and values to the user verbatim — show every field and all of its values; do not pre-select, summarize, or omit any. Do not call `get_search_results` until the user has explicitly selected filters or confirmed that no filters should be applied.

#### 3. Get filtered results (only after user has responded to filter_options)

Array params: `site`, `season`, `free_state`, `video_code`, `edition`, `resolution`, `release_group` — OR within a field, AND across fields.
`title_pattern`: regex string for torrent title matching (e.g., `4K|2160p|UHD`). Use only when user explicitly requests pattern matching.
`show_filter_options=true`: re-check available filters only, not for fetching results.

Filter values must come from the `filter_options` returned by `search_torrents` in step 2 — do not invent, translate, normalize, or use values from any other source. Note: `filter_options` keys are camelCase (e.g., `freeState`), but `get_search_results` params are snake_case (e.g., `free_state`).

```bash
node scripts/mp-cli.js get_search_results resolution='1080p,2160p' free_state='免费,50%'
```

If empty, tell the user which filter to relax and ask before retrying.

#### 4. Present results as a numbered list

Show all results without pre-selection. Each row: index, title, size, seeders, resolution, release group (verbatim, keep `@` etc.), `volume_factor`, `freedate_diff`.

| `volume_factor` | Meaning |
|---|---|
| `免费` | Free download |
| `50%` | 50% download size |
| `2X` | Double upload |
| `2X免费` | Double upload + free |
| `普通` | No discount |

`freedate_diff`: remaining free window (e.g., `2天3小时`).

#### 5. Check before downloading

After user picks, run **Check Library and Subscriptions** (see section below) before calling `add_download`. If the media already exists in the library or is already subscribed, stop and tell the user what was found — do not call `add_download` until the user explicitly confirms they still want to proceed.

#### 6. Add download

`torrent_url` comes from the `torrent_url` field in `get_search_results` output.

```bash
node scripts/mp-cli.js add_download torrent_url="abc1234:1,def5678:2"  # comma-separated for multiple
```

#### Error handling

| Step | Action |
|---|---|
| `search_media` empty | Retry with alternative title (English/original), inform user. Still empty → ask for title or TMDB ID. |
| `search_torrents` empty | Inform user, ask whether to retry with different sites. |
| `get_search_results` empty | Do not silently broaden filters. Suggest which filter to relax, ask before retrying. |
| `add_download` fails | Run `query_downloaders` + `query_download_tasks` to diagnose, then report to user. |

### Add Subscription

1. `search_media` to get `tmdb_id`
2. Run **Check Library and Subscriptions**
3. If user specified a season, run **Season Validation** to get correct `season` and `start_episode` — must complete before calling `add_subscribe`

Pass `start_episode=` when the user's season maps to a mid-season episode range (e.g., user call it "Season 2" but TMDB has Season 1, episodes starting at 13).

```bash
node scripts/mp-cli.js add_subscribe title="..." year="2011" media_type="tv" tmdb_id=42009
node scripts/mp-cli.js add_subscribe title="..." year="2011" media_type="tv" tmdb_id=42009 season=4
node scripts/mp-cli.js add_subscribe title="..." year="2024" media_type="tv" tmdb_id=12345 season=1 start_episode=13
```

### Manage Downloads

```bash
node scripts/mp-cli.js query_download_tasks status=downloading        # list tasks, get hash for deletion
node scripts/mp-cli.js delete_download hash=<hash>                    # confirm with user first (irreversible)
node scripts/mp-cli.js delete_download hash=<hash> delete_files=true  # also remove files
```

### Manage Subscriptions

```bash
node scripts/mp-cli.js query_subscribes status=R                            # list active
node scripts/mp-cli.js update_subscribe subscribe_id=123 resolution="1080p" # update filters
node scripts/mp-cli.js search_subscribe subscribe_id=123                    # search missing episodes — confirm first
node scripts/mp-cli.js delete_subscribe subscribe_id=123                    # remove — confirm first
```

### Check Library and Subscriptions

Run before any download or subscription to avoid duplicates:

```bash
node scripts/mp-cli.js query_library_exists tmdb_id=123456 media_type="movie"
node scripts/mp-cli.js query_subscribes tmdb_id=123456
```

If already in library or already subscribed, stop and report the finding to the user. Do not proceed with download or subscription until the user explicitly confirms they still want to continue. Otherwise continue directly.

### Season Validation

Mandatory when user specifies a season. Productions sometimes release a show in multiple parts under one TMDB season; online communities and torrent sites may label each part as a separate "season".

#### 1. Verify season exists

```bash
node scripts/mp-cli.js query_media_detail tmdb_id=<id> media_type="tv"
```

Check `season_info` against the user's requested season:

- **Season exists:** use that season number directly, proceed to torrent search.
- **Season does not exist:** the user's "season" likely maps to a later episode range within an existing TMDB season. Note the latest (highest-numbered) season from `season_info`, then continue to step 2.

#### 2. Identify the correct episode range

Take the latest season number from step 1's `season_info` and pass it as the `season=` parameter:

```bash
node scripts/mp-cli.js query_episode_schedule tmdb_id=<id> season=<latest_season_from_season_info>
```

Use `air_date` to find a block of recently-aired episodes that likely corresponds to what the user calls the missing season. Look for a gap in `air_date` between episodes — the gap indicates a part break, and the episodes after the gap are what the user likely refers to as the next "season". For example, if TMDB Season 1 has episodes 1–24 and there is a multi-month gap between episode 12 and 13, then episodes 13–24 correspond to the user's "Season 2". If no such gap exists, tell user content is unavailable. Otherwise confirm the episode range with user.

## Error handling
**Missing configuration:** Ask the user for the backend host and API key. Once provided, run `node scripts/mp-cli.js -h <HOST> -k <KEY>` (no command) to save the config persistently — subsequent commands will use it automatically.
