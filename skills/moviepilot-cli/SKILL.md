---
name: moviepilot-cli
description: Use this skill when the user wants to manage a home media ecosystem via MoviePilot. Covers searching movies/TV shows/anime, managing subscriptions, controlling downloads (torrent search, quality filtering), monitoring download progress, and organizing media libraries. Trigger when user mentions movie/show titles, asks about subscriptions, downloads, library organization, or references MoviePilot directly.
---

# MoviePilot Media Management Skill

## Overview

This skill interacts with the MoviePilot backend via the Node.js command-line script `scripts/mp-cli.js`. It supports four core capabilities: media search and recognition, subscription management, download control, and media library organization.

## CLI Reference

```
Usage: mp-cli.js [-h HOST] [-k KEY] [COMMAND] [ARGS...]

Options:
    -h HOST  backend host
    -k KEY   API key

Commands:
    (no command)        save config when -h and -k are provided
    list                list all commands
    show <command>      show command details and usage example
    <command> [k=v...]  run a command
```

## Discovering Available Tools

Before performing any task, use these two commands to understand what the current environment supports.

**List all available commands:**

```bash
node scripts/mp-cli.js list
```

**Inspect a command's parameters:**

```bash
node scripts/mp-cli.js show <command>
```

`show` displays a command's name, its parameters, and a usage example. For each parameter, it shows the name, type, required/optional status, and description. **Always run `show` before calling any command** — never guess parameter names or formats.

## Standard Workflow

Follow this sequence for any media task:

```
1. list                  → confirm which commands are available
2. show <command>        → confirm parameter format before calling
3. Search / recognize    → resolve exact metadata (TMDB ID, season, episode)
4. Check library / subs  → avoid duplicate downloads or subscriptions
5. Execute action        → downloads require explicit user confirmation first
6. Confirm final state   → report the outcome to the user
```

## Tool Calling Strategy

**Fallback search**: If a media search returns no results, try in order: fuzzy recognition → web search → ask the user for more information.

**Disambiguation**: If search results are ambiguous, call the detail-query command to obtain precise metadata before proceeding.

## Download Safety Rules

Before executing any download command, you **must**:

1. Search for and retrieve a list of available torrent resources.
2. Present torrent details to the user (size, seeders, quality, release group).
3. **Wait for explicit user confirmation** before initiating the download.

## Error Handling

| Error                 | Resolution                                                                  |
| --------------------- | --------------------------------------------------------------------------- |
| No search results     | Try fuzzy recognition → web search → ask the user                           |
| Download failure      | Check downloader status; advise user to verify disk space                   |
| Missing configuration | Prompt user to run `node scripts/mp-cli.js -h <HOST> -k <KEY>` to configure |
