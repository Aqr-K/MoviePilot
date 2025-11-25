# 工具命名和功能混淆分析报告

## 一、潜在混淆点分析

### 1. 媒体相关工具（高风险混淆）

#### 1.1 `search_media` vs `recognize_media` vs `scrape_metadata`
**当前状态：**
- `search_media`: 在TMDB数据库中搜索媒体（按标题、年份等条件搜索）
- `recognize_media`: 从种子标题或文件路径识别媒体信息
- `scrape_metadata`: 为文件或目录刮削元数据（生成NFO文件等）

**混淆风险：** ⚠️ **中等**
- 三个工具都涉及"媒体"，但功能完全不同
- `search_media` 是数据库搜索，`recognize_media` 是信息识别，`scrape_metadata` 是文件操作
- 描述已区分，但命名可能让智能体混淆

**建议：**
- ✅ 描述已清晰区分，无需修改
- 可考虑在描述中更明确强调差异：
  - `search_media`: "Search for media in TMDB database by title/year/type"
  - `recognize_media`: "Extract/identify media info from torrent titles or file paths"
  - `scrape_metadata`: "Generate metadata files (NFO, posters) for existing media files"

### 2. 目录相关工具（高风险混淆）

#### 2.1 `query_directories` vs `list_directory`
**当前状态：**
- `query_directories`: 查询系统目录配置（配置信息，如下载目录、媒体库目录的设置）
- `list_directory`: 列出文件系统目录内容（实际文件和文件夹）

**混淆风险：** ⚠️⚠️ **高**
- 两个工具都涉及"目录"，但一个是配置查询，一个是文件列表
- 命名相似，容易混淆

**建议：**
- 考虑重命名 `query_directories` 为 `query_directory_config` 或 `query_directory_settings`
- 或者在描述中更明确：
  - `query_directories`: "Query directory **configuration settings** (download/library paths, storage types, etc.)"
  - `list_directory`: "List **actual files and folders** in a file system directory"

### 3. 媒体库查询工具（低风险）

#### 3.1 `query_media_library` vs `query_media_latest`
**当前状态：**
- `query_media_library`: 检查特定媒体是否存在于媒体库中
- `query_media_latest`: 查询媒体服务器最近入库的影片列表

**混淆风险：** ✅ **低**
- 命名清晰，功能区分明确
- 描述已明确说明差异

### 4. 订阅相关工具（低风险）

#### 4.1 `search_subscribe` vs `query_subscribes`
**当前状态：**
- `search_subscribe`: 搜索订阅的缺失剧集（执行搜索和下载操作）
- `query_subscribes`: 查询订阅状态和列表（只查询，不执行操作）

**混淆风险：** ✅ **低**
- `search` vs `query` 已明确区分操作类型
- 描述清晰

#### 4.2 多个订阅查询工具
- `query_subscribes`: 查询所有订阅
- `query_subscribe_history`: 查询订阅历史
- `query_subscribe_shares`: 查询共享订阅
- `query_popular_subscribes`: 查询热门订阅

**混淆风险：** ✅ **低**
- 命名清晰，通过后缀区分功能

### 5. 下载相关工具（低风险）

#### 5.1 `query_downloads` vs `query_downloaders`
**当前状态：**
- `query_downloads`: 查询下载任务状态
- `query_downloaders`: 查询下载器配置

**混淆风险：** ✅ **低**
- 命名清晰，单复数已区分

### 6. 调度器/工作流工具（低风险）

#### 6.1 `query_schedulers` vs `run_scheduler`
**当前状态：**
- `query_schedulers`: 查询调度器任务列表
- `run_scheduler`: 运行调度器任务

**混淆风险：** ✅ **低**
- `query` vs `run` 已明确区分

#### 6.2 `query_workflows` vs `run_workflow`
**当前状态：**
- `query_workflows`: 查询工作流列表
- `run_workflow`: 运行工作流

**混淆风险：** ✅ **低**
- `query` vs `run` 已明确区分

## 二、命名规范分析

### 命名模式总结：
1. **Search类** (`search_*`): 执行搜索操作
   - `search_media`, `search_person`, `search_torrents`, `search_subscribe`, `search_web`
   
2. **Query类** (`query_*`): 查询信息（只读）
   - `query_*`: 各种查询工具
   
3. **Add/Update/Delete类**: 执行操作
   - `add_*`, `update_*`, `delete_*`
   
4. **Run类**: 执行任务
   - `run_scheduler`, `run_workflow`

### 命名一致性：✅ 良好
- 命名模式统一，易于理解
- 动词选择恰当（search/query/add/update/delete/run）

## 三、建议优化

### 高优先级（建议修改）

1. **`query_directories` 重命名或增强描述**
   - 建议：在描述中明确强调是"配置查询"而非"文件列表"
   - 或考虑重命名为 `query_directory_config`

### 中优先级（可选优化）

1. **`search_media`、`recognize_media`、`scrape_metadata` 的描述增强**
   - 在描述开头明确说明数据源/操作类型
   - 例如：`search_media`: "Search TMDB database for media..."
   - 例如：`recognize_media`: "Extract media info from torrent titles or file paths..."
   - 例如：`scrape_metadata`: "Generate metadata files for existing media files..."

### 低优先级（当前已足够清晰）

- 其他工具命名和描述已足够清晰，无需修改

## 四、总结

**总体评价：** ✅ **良好**

大部分工具的命名和描述已经足够清晰，只有少数几个地方存在潜在的混淆风险：

1. **`query_directories` vs `list_directory`** - 需要更明确的区分
2. **媒体相关三个工具** - 描述可以更明确强调差异

建议优先处理 `query_directories` 的描述或命名，其他工具当前状态已足够清晰。

