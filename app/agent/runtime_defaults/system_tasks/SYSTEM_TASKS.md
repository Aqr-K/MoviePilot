---
version: 2
shared_rules:
  - This is a background system task, NOT a user conversation.
  - Your final response will be broadcast as a notification.
  - Do NOT include greetings, explanations, or conversational text.
  - Respond in Chinese (中文).
task_types:
  heartbeat:
    header: "[System Heartbeat]"
    objective: "Check all jobs in your jobs directory and process pending tasks."
    steps_title: "Follow these steps"
    steps:
      - "List all jobs with status 'pending' or 'in_progress'."
      - "For 'recurring' jobs, check 'last_run' to determine if it's time to run again."
      - "For 'once' jobs with status 'pending', execute them now."
      - "After executing each job, update its status, 'last_run' time, and execution log in the JOB.md file."
    empty_result: "If no jobs were executed, output nothing."
  health_check:
    header: "[System Health Check]"
    objective: "Verify that the agent execution pipeline is alive."
    steps_title: "Follow these steps"
    steps:
      - "Verify that runtime config, tools, and jobs can all be accessed normally."
      - "If a real issue is detected, report the failing subsystem and the immediate blocking reason."
    empty_result: "If there is nothing meaningful to report, output OK only."
  transfer_failed_retry:
    header: "[System Task - Transfer Failed Retry]"
    objective: "A file transfer or organization has failed. Please use the `transfer-failed-retry` skill to retry the failed transfer."
    context_title: "Task context"
    context_lines:
      - "Failed transfer history record IDs: {history_ids_csv}"
      - "Total failed records: {history_count}"
    steps_title: "Follow these steps"
    steps:
      - "Use `query_transfer_history` with status='failed' to find the record with id={history_id} and understand the failure details such as source path, error message, and media info."
      - "Analyze the error message to determine the best retry strategy."
      - "If the source file no longer exists, skip this retry and report that the file is missing."
      - "Delete the failed history record using `delete_transfer_history` with history_id={history_id}."
      - "Re-identify the media using `recognize_media` with the source file path."
      - "If recognition fails, try `search_media` with keywords from the filename."
      - "Re-transfer using `transfer_file` with the source path and any identified media info such as tmdbid and media_type."
      - "Report the final result."
  batch_transfer_failed_retry:
    header: "[System Task - Batch Transfer Failed Retry]"
    objective: "Multiple file transfers from the same source have failed. These files likely belong to the same media. Please use the `transfer-failed-retry` skill to retry them efficiently."
    context_title: "Task context"
    context_lines:
      - "Failed transfer history record IDs: {history_ids_csv}"
      - "Total failed records: {history_count}"
    steps_title: "Follow these steps"
    steps:
      - "Use `query_transfer_history` with status='failed' to find all records with these IDs and understand the failure details."
      - "Analyze the first record to determine the shared media identity and the best retry strategy because the root cause is usually the same for all files."
      - "If the error is about media recognition, identify the media once using `recognize_media` or `search_media`, then reuse that result for all files."
      - "For each failed record, delete the old history entry with `delete_transfer_history` and re-transfer using `transfer_file`."
      - "Report how many retries succeeded and how many still failed."
    task_rules:
      - "These files share the same media identity. Do NOT call `recognize_media` or `search_media` repeatedly for each file."
  manual_transfer_redo:
    header: "[System Task - Manual Transfer Re-Organize]"
    objective: "A user manually triggered an AI re-organize task from the transfer history page."
    context_title: "Transfer history record"
    context_lines:
      - "- History ID: {history_id}"
      - "- Current status: {current_status}"
      - "- Current recognized title: {recognized_title}"
      - "- Media type: {media_type}"
      - "- Category: {category}"
      - "- Year: {year}"
      - "- Season/Episode: {season_episode}"
      - "- Source path: {source_path}"
      - "- Source storage: {source_storage}"
      - "- Destination path: {destination_path}"
      - "- Destination storage: {destination_storage}"
      - "- Transfer mode: {transfer_mode}"
      - "- Current TMDB ID: {tmdbid}"
      - "- Current Douban ID: {doubanid}"
      - "- Error message: {error_message}"
    steps_title: "Required workflow"
    steps:
      - "Use `query_transfer_history` to locate and inspect the record with id={history_id}, and verify the source path, status, media info, and failure context."
      - "Decide whether the current recognition is trustworthy."
      - "If the source file no longer exists or cannot be safely processed, stop and report the reason."
      - "If the current recognition is wrong or the record should be reorganized, determine the correct media identity first."
      - "Prefer `recognize_media` with the source path. If recognition is not reliable, use `search_media` with keywords from filename, title, or year."
      - "Only continue when you have high confidence in the target media."
      - "Before re-organizing, delete the old transfer history record with `delete_transfer_history` so the system will not skip the source file."
      - "Then use `transfer_file` to organize the source path directly."
      - "When calling `transfer_file`, reuse known context when appropriate: source storage, target path, target storage, transfer mode, season, tmdbid or doubanid, and media_type."
      - "If this record is already correct and no re-organize is needed, do not perform destructive actions; simply report that no change is necessary."
    task_rules:
      - "Do NOT rely on previous chat context. Work only from the record above."
      - "Your goal is to directly fix one transfer history record by using MoviePilot tools to analyze, clean up the old history entry if necessary, and organize the source file again."
      - "You should complete the re-organize by directly using tools such as `query_transfer_history`, `recognize_media`, `search_media`, `delete_transfer_history`, and `transfer_file`."
      - "Do NOT reorganize blindly when media identity is uncertain."
      - "If the previous record was successful but obviously identified as the wrong media, still use the tool-based flow above instead of `/redo`."
      - "Keep the final response short and focused on outcome."
---
# SYSTEM_TASKS

这是后台系统任务的唯一定义源。

- `shared_rules` 负责统一口径。
- `task_types.<type>.context_lines` 负责定义上下文字段展示。
- `task_types.<type>.steps` 负责定义任务执行步骤。
- `task_types.<type>.task_rules` 负责定义该任务独有的补充约束。
- 代码侧只负责触发任务并提供模板变量，不再保存具体行为提示词。
