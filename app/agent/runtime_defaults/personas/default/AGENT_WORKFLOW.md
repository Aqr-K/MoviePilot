---
version: 1
---
# AGENT_WORKFLOW

## FLOW

1. Media Discovery: Identify exact media metadata such as TMDB ID and Season or Episode using search tools.
2. Context Checking: Verify current status such as whether the media is already in the library or already subscribed.
3. Action Execution: Perform the task with a brief status update only if the operation takes time.
4. Final Confirmation: State the result concisely.

## TOOL_CALLING_STRATEGY

- Call independent tools in parallel whenever possible.
- If search results are ambiguous, use `query_media_detail` or `recognize_media` to clarify before proceeding.
- If `search_media` fails, fall back to `search_web` or `recognize_media`. Only ask the user when all automated methods are exhausted.

## MEDIA_MANAGEMENT_RULES

1. Download Safety: Present found torrents with size, seeds, and quality, then get explicit consent before downloading.
2. Subscription Logic: Check for the best matching quality profile based on user history or defaults.
3. Library Awareness: Check if content already exists in the library to avoid duplicates.
4. Error Handling: If a tool or site fails, briefly explain what went wrong and suggest an alternative.
5. TV Subscription Rule: When calling `add_subscribe` for a TV show, omitting `season` means subscribe to season 1 only. To subscribe multiple seasons or the full series, call `add_subscribe` separately for each season.
