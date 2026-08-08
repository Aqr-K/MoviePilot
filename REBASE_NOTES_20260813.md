# v3-python 变基到官方 upstream/v3（2026-08-13）

## 目标
把 `v3-python` 的上游从 `origin/v3-python` 改为官方 `upstream/v3`，并在其之上重新变基。
用户已确认：**保留 16 个主题提交逐个重放**；**只做本地，force push 另行确认**。

## 已完成的准备
- 备份分支 `backup/v3-python-pre-rebase-20260813` = `53c132e7c`（本地）
- `git branch --set-upstream-to=upstream/v3 v3-python`，并设 `branch.v3-python.pushRemote=origin`（防裸 push 推到官方仓库）
- 工作目录：`.claude/worktrees/v3-rebase`，分支 `v3-python`
- 基线 `415ccda6a` → 目标 `eebd81a0e`（ahead 16 / behind 103）
- 变基进行中：`git rebase upstream/v3`，`b6ea3ee1e` 被自动跳过（上游 `3eed518f8` 已含同一 patch）

## 解冲突的通用判定（已验证有效）
1. **上游语义优先**：凡上游这轮改过的行为（新参数、新守卫、新字段），必须保留；我方只保留「结构」（拆包/门面/落点重定向/2.0 写法）。
2. **每个冲突文件先做预检**：`git diff 415ccda6a upstream/v3 -- <path>`，确认上游是否也改过；**我方新建的抽出模块不会自动带上上游改动，必须手工迁移**（已在 media_interaction.py / plugin_manager.py 命中此坑）。
3. **删除类冲突（我方把类迁走）**：先把上游对该类的 diff 迁到新落点，再删原处。
4. **import 冲突**：逐符号 grep 计数，区外仍被使用的必须保留（已救回 `ResponseAPIRouter`/`RAW_RESPONSE_OPENAPI_KEY`/`or_`/`mfa_endpoint`）。

## 上游本轮的主要契约变更（影响所有后续冲突）
- **媒体身份统一**：`tmdbid/doubanid/bangumiid/anilistid/imdbid/tvdbid/source/mediaid` → **`media_source` + `media_id`**（DB 模型、schema、chain 调用全线）。
- `recognize_media`/`async_recognize_media` 新增 `music_type`；实现抽出 `_run_native_media_recognize` / `_supplement_media_recognize` / `_media_info_has_identity`。
- `search_medias`/`search_persons`/`search_collections` 参数 `source` → `media_source`。
- `snapshot_storage` 新增 `previous_snapshot`（monitor 增量对账依赖，测试有断言）。
- `obtain_images` 新增「音乐类型直接返回」守卫。
- 插件市场：`VERSION_BACKWARD_COMPATIBLE_FLAGS` + `PluginHelper.is_package_plugin_compatible`；agent 工具构建加 `AGENT_TOOLS_BUILD_MAX_ATTEMPTS`。
- 全线 music 字段：`music_type`/`total_tracks`/`audio_quality`/`audio_format`/`min_bitrate`/`min_bit_depth`/`min_sample_rate`/`current_*`。

## 已解决的提交（进度 8/15）
1-3. 自动应用（core 迁出、event 拆包、module 拆包）
4. `a98e513b6` dispatch 统一 — chain/__init__.py(16处) + storage.py + filemanager + schemas/transfer.py；`_strict` 并入 `module_kwargs`；两边新增类都保留
5. `6ea3938a1` message 拆分 — 删 message.py 内 MediaInteractionChain(1542行)，**上游 3 处身份参数改动已迁入 media_interaction.py**
6. `d80d8c0d2` plugin 迁出 — core/plugin.py 保留 18 行垫片；上游 83 行改动经 `sed` 重定向 `git apply --3way` 落到 helper/plugin_manager.py；seam 用 `get_plugin_source().is_package_plugin_compatible`
7. `e2b517813` DB 2.0 — 6 个模型；规则=**上游字段集 + 我方 Mapped/mapped_column 写法**；脚本 `/tmp/resolve_models.py`
8. `20d36c965` auth 框架 — schemas/mfa.py 上游输出模型+我方请求模型合并；login/auth 端点采我方 flow service + 上游 ResponseAPIRouter/openapi_extra；**给 `schemas.AuthProviderInfo` 补 `login_url`/`flow`**，否则上游类型化 response_model 会静默丢弃我方流程入口字段

## 当前停在
**9/15 `5b84c3491` refactor(transfer): TransferChain 拆分为队列/刮削/结果三服务**
冲突：`app/chain/transfer.py`、`tests/test_transfer_job_manager.py`

## 剩余提交
10 `755ceb832` api 端点下沉 service
11 `be3b5dc7f` DI 组合根 ServiceRegistry
12 `4ac25e706` P0/P1/P2 安全加固
13 `c376663e3` 注释改描述现状
14 `3c0ca5a6a` 图片代理路径穿越 + 存储凭据泄露
15 `53c132e7c` think 死循环DoS + 关停死锁 + Alist 截断

## 收尾清单（变基完成后必做）
- [ ] alembic 单 head 校验（上游有 `chore(database): align v3 migration filenames` + 迁移链加固，我方 DB 提交可能撞车）
- [ ] 全量测试：`python tests/run.py`；解释器**必须**用 `/home/vscode/.local/share/uv/python/cpython-3.12.13-linux-x86_64-gnu/bin/python3.12`
- [ ] 确认 `schemas/mfa.py` 的 `credential: dict` 是否收紧为上游的 `dict[str, JsonData]`
- [ ] 汇报后再由用户确认是否 force push origin/v3-python

## 9/15 `5b84c3491` transfer 拆服务 — 现场分析（重要）
该提交**不新建文件**，三个服务类就定义在 `app/chain/transfer.py` 内，且已随自动合并落位：
- `TransferService`(L973) / `ScrapeBatchCoordinator`(L1146) / `TransferResultProcessor`(L1290) / `TransferChain`(L1645)

8 处冲突的「上游侧」= 这些方法**留在 TransferChain 里的旧位置**；「我方侧」几乎为空（因为已搬进服务类）。
⚠️ 但我方服务类是基于 `415ccda6a` 抽出的，**不含上游本轮 823 行改动**。因此每个冲突块必须：
1. 删除上游侧（方法确已搬走，用 `grep -n "def <name>"` 确认服务类内存在）；
2. **把上游本轮对该方法的改动 diff 出来，迁移进服务类**（否则静默丢失 FUSE 修复 #6276 与音乐重试）。

上游本轮在 transfer.py 的新增（冲突区外、已自动并入 TransferChain，注意与服务类的状态耦合）：
`replay_pending`(L2444) / `__register_pending`(L2527) / `__discard_pending` / `__build_replay_fileitem` —— FUSE 挂载无响应导致的 pending 重放；
`get_job_id`(L223) / `pending_total` 在 JobManager；音乐重试 `_match_music_album_context` / `_download_history_music_type` / `_is_music_retry_source` / `_recognize_music_retry_media`。

冲突清单（行号为解冲突前）：
#1 L1689 `__init__`尾+`__init`+`__stop` → 我方委派 `self._service.start()`；上游队列状态字段需确认已在 TransferService
#2 L2042 `__is_overwrite_declined`+`__default_callback`(373行) → 迁 TransferResultProcessor
#3 L2430 入队注释（小）
#4 L2610 `__send_metadata_scrape_event`+`__build_metadata_scrape_payload` → ScrapeBatchCoordinator(我方版在 L1614)
#5 L2673 `__record_scrape_target`/`__finish_scrape_batch_task`/`__flush_scrape_batch_if_ready` → ScrapeBatchCoordinator
#6 L2852 `__start_transfer`(111行) → TransferService
#7 L3058 / #8 L3113 `__handle_transfer` 内的识别/图片块（我方已拆 helper）

### 9/15 各冲突块的逐块判定（已核实，勿再重新推导）
- **#1** L1689：取**我方侧**（`_service.start()` 委派）。上游 `__init`/`__stop` 已由 `TransferService.start/stop` 承接。
- **#2** L2042：取**我方侧**（空），但须把上游**新增** `__is_overwrite_declined`(27行) 迁入 `TransferResultProcessor`，并把 `__default_callback` 的上游改动（+28行，含 `job_id = self.jobview.get_job_id(task)`）合入 `TransferResultProcessor.handle/_handle_transfer_failure`。
- **#3** L2430：**两侧合并** → `self._service.enqueue(task=task, callback=self._result_processor.handle)` **+ 上游新增的 `self.__register_pending(task)`**（FUSE 落盘登记，漏件防护，必须保留）。
- **#4** L2610：取我方侧；上游**新增** `__build_metadata_scrape_payload`(26行) 迁入 `TransferResultProcessor.__send_metadata_scrape_event`(L1614) 一并使用；上游同时**删除**了 `or task.mediainfo.type == MediaType.MUSIC` 排除条件（音乐现在也要刮削）。
- **#5** L2673：取我方侧；上游改动迁入 `ScrapeBatchCoordinator.record_target/_flush_if_ready`：新增 `"file_contexts": {}`、音乐(MusicInfo)逐文件写 `file_contexts[target_file]={path,meta,mediainfo}`、`_flush_if_ready` 组装 `payload` 时按 `file_list` 顺序附 `file_contexts` 列表；同样删除音乐排除条件。
- **#6** L2852：取我方侧；上游改动迁入 `TransferService.run_worker`：`current_total = self._processed_num + self.jobview.pending_total()`（原 `self.jobview.total()`，修进度分母虚高/跨批连坐）。
- **#7** L3058 与 **#8** L3113：**取上游侧**（我方侧是抽 helper 前的旧版，仍用已废弃的 `recognize_kwargs["source"]`）。上游含：`media_source/media_id` 识别、`music_type=self._download_history_music_type(...)`、`history_year_conflict` 年份冲突重识别、`MetaMusic` 音乐兜底、`record_transfer_failure` 失败登记。

方法级 diff 全文见 worktree 根 `TRANSFER_UPSTREAM_DIFFS.txt`。
