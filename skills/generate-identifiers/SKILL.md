---
name: generate-identifiers
description: >-
  Use this skill when a user provides a torrent name or file name and wants to fix recognition issues,
  or asks to add/manage custom identifiers (自定义识别词).
  This skill generates identifier rules based on the WordsMatcher preprocessing logic,
  checks for duplicates against existing rules, and saves them via MCP tools.
  Applicable scenarios include:
  1) A torrent or file name is incorrectly recognized (wrong title, season, episode, etc.);
  2) The user wants to block unwanted keywords from torrent names;
  3) The user needs episode offset rules for series with non-standard numbering;
  4) The user wants to force recognition of a specific media by TMDB/Douban ID.
allowed-tools: query_custom_identifiers update_custom_identifiers recognize_media
---

# Generate Custom Identifiers (生成自定义识别词)

This skill helps generate custom identifier rules for MoviePilot's media recognition system. Custom identifiers preprocess torrent/file names before the recognition engine runs, correcting naming issues that cause misidentification.

## Prerequisites

You need the following tools:
- `query_custom_identifiers` - Query all existing custom identifier rules
- `update_custom_identifiers` - Save the updated identifier list (replaces the full list)
- `recognize_media` - Test recognition of a torrent title or file path (optional, for verification)

## Supported Rule Formats

There are **four formats**. Operators must have spaces on both sides.

### 1. Block Word (屏蔽词)

Removes matched text from the title. Supports regex.

```
REPACK
```

### 2. Replacement (被替换词 => 替换词)

Regex substitution. The left side is a regex pattern, the right side is the replacement (supports backreferences).

```
被替换词 => 替换词
```

**Special replacement for direct ID specification:**
```
被替换词 => {[tmdbid=xxx;type=movie/tv;s=xxx;e=xxx]}
被替换词 => {[doubanid=xxx;type=movie/tv;s=xxx;e=xxx]}
```
Where `s` (season) and `e` (episode) are optional.

### 3. Episode Offset (集偏移)

Shifts episode numbers found between the front and back delimiter words. `EP` is the placeholder for the original episode number.

```
前定位词 <> 后定位词 >> EP-12
```

### 4. Combined Replacement + Episode Offset

First performs replacement; episode offset only runs if replacement succeeded.

```
被替换词 => 替换词 && 前定位词 <> 后定位词 >> EP-12
```

### Comments

Lines starting with `#` are comments and will be skipped during processing.

## Important Rules for Writing Identifiers

1. **Regex support**: All patterns support regular expressions. Special characters (`. * + ? ^ $ { } [ ] ( ) | \`) must be escaped with `\` when matching literally.
2. **Spaces matter**: The operators ` => `, ` <> `, ` >> `, ` && ` must have spaces on both sides.
3. **One rule per string**: Each element in the identifiers list is one rule.
4. **EP placeholder**: In episode offset expressions, `EP` represents the original episode number. Common patterns:
   - `EP-12` means subtract 12
   - `EP+5` means add 5
   - `EP*2` means multiply by 2
5. **Chinese number support**: Episode offset handles Chinese numbers (一二三四五六七八九十).
6. **Empty replacement**: Using nothing after `=>` is equivalent to a block word.

## Workflow

### Step 1: Analyze the Problem

Parse the torrent/file name provided by the user. Identify:
- What is being incorrectly recognized (title, season, episode, year, quality, etc.)
- What the correct recognition result should be
- Which identifier format(s) will solve the problem

### Step 2: Generate the Identifier Rule(s)

Write the rule using the appropriate format. Ensure:
- Regex special characters are properly escaped
- Add a comment line (starting with `#`) above the rule to describe what it does
- Test the regex mentally against the provided name to verify correctness

### Step 3: Query Existing Identifiers

Use the `query_custom_identifiers` tool to get all current rules:

```
query_custom_identifiers(explanation="Checking existing identifiers before adding new rules to avoid duplicates")
```

### Step 4: Check for Duplicates

Compare each new rule against the existing identifiers:
- **Exact duplicate**: The rule string is identical to an existing rule — skip it
- **Functional duplicate**: A different rule that produces the same effect on the same input (e.g., same regex pattern with trivial whitespace differences) — warn the user
- **Conflict**: An existing rule modifies the same text in a different way — warn the user and ask which to keep

### Step 5: Save the Updated Identifiers

Merge new non-duplicate rules into the existing list, then use `update_custom_identifiers` to save the **complete** list:

```
update_custom_identifiers(
    explanation="Adding new identifier rules for [description]",
    identifiers=["existing rule 1", "existing rule 2", "# new comment", "new rule"]
)
```

**CRITICAL**: Always include ALL existing rules in the list. This tool replaces the entire list.

### Step 6: Verify (Optional)

If the user wants to verify the rule works, use `recognize_media` to test:

```
recognize_media(explanation="Testing recognition after adding identifier", title="the torrent title to test")
```

### Step 7: Report

Tell the user:
- What rule(s) were added
- What effect they will have on the title
- Whether any duplicates or conflicts were found

## Common Scenarios and Examples

### Wrong Season/Episode Parsing

**User**: "种子名 `[SubGroup] My Show - 13 [1080P]`，这是第二季第1集，但被识别成第13集"

**Solution**: Episode offset to subtract 12:
```
# My Show 第二季集数偏移（13->1）
\[SubGroup\] <> \[1080P\] >> EP-12
```

### Unwanted Text Causing Wrong Identification

**User**: "种子名 `My.Show.2024.REPACK.1080p.mkv`，REPACK导致识别异常"

**Solution**: Block word:
```
# 屏蔽REPACK标记
REPACK
```

### Non-Standard Naming

**User**: "文件名 `[OldName] EP01.mkv`，应该识别为 NewName"

**Solution**: Replacement:
```
# OldName替换为NewName
OldName => NewName
```

### Force TMDB ID Recognition

**User**: "种子名 `Some.Weird.Name.S01E01.1080p.mkv`，识别不到，TMDB ID是12345，是电视剧"

**Solution**: Direct ID specification:
```
# 强制识别Some.Weird.Name为TMDB ID 12345
Some\.Weird\.Name => {[tmdbid=12345;type=tv;s=1]}
```

### Combined Fix

**User**: "种子名 `[Baha][OldTitle][13][1080P]`，标题应该是NewTitle，而且13应该是第二季第1集"

**Solution**: Combined replacement + episode offset:
```
# OldTitle替换为NewTitle并偏移集数
OldTitle => NewTitle && \[Baha\] <> \[1080P\] >> EP-12
```

### Multiple Episode Numbers in One Title

**User**: "种子名 `[Group] Title - 13-14 [1080P]`，应该是第1-2集"

**Solution**: Episode offset (handles multiple numbers between delimiters):
```
# Title 集数偏移
\[Group\] <> \[1080P\] >> EP-12
```

## WordsMatcher Processing Logic Reference

The `WordsMatcher.prepare()` method (in `app/core/meta/words.py`) processes each rule in order:

1. Skip empty lines and lines starting with `#`
2. Detect format by checking operator presence:
   - Contains ` => ` AND ` && ` AND ` >> ` AND ` <> ` → Combined format (4)
   - Contains ` => ` → Replacement format (2)
   - Contains ` >> ` AND ` <> ` → Episode offset format (3)
   - Otherwise → Block word format (1)
3. For combined format, replacement runs first; episode offset only runs if replacement succeeded
4. Returns the modified title and a list of rules that were actually applied
5. Priority: per-subscribe `custom_words` parameter takes precedence over global `CustomIdentifiers`

## Safety Notes

- Always query existing rules first before updating
- Never remove existing rules unless the user explicitly asks
- Add comment lines before new rules for maintainability
- When uncertain about the correct approach, present multiple options and let the user choose
