# 后端 PR 提交顺序

当前依赖序列为 **14 个 PR**，已将相邻零碎单元整合。代码锚点为 `6544f02a40a8135710649fbfff7ce73a7af5f0a3`，产品目录树仍为 `6f239ace264c5e555501ef2912987b2a813d0f3b`。准确父子关系、源码树及验收复用来源见 [源码索引](source-index.json)。

官方独立前置仍分别处理。查询时 #7638、#7640、#7642、#7643 已由官方合入，#7639 尚待审阅；此后状态以官方 PR 为准。此次整合不合并、发布或重写官方分支。

依赖单元继续在 fork 逐级审阅。官方前置完成后，按下表顺序逐个移交到当时的官方基线。前置聚合分支只用于提供依赖，不能作为大 PR 一次移交。

| 顺序 | PR | 审查职责 | 实现锚点 |
| --- | --- | --- | --- |
| 1 | [#103](https://github.com/Aqr-K/MoviePilot/pull/103) | 平台扩展契约与内置身份事实 | `76339baad` |
| 2 | [#105](https://github.com/Aqr-K/MoviePilot/pull/105) | 连接资源、规则配置与固定离线升级 | `63ce0b7ef` |
| 3 | [#106](https://github.com/Aqr-K/MoviePilot/pull/106) | 规范授权服务与仓储 | `fc25e1d74` |
| 4 | [#108](https://github.com/Aqr-K/MoviePilot/pull/108) | 订阅及下载业务归属与提交前复核 | `eadd0a21e` |
| 5 | [#109](https://github.com/Aqr-K/MoviePilot/pull/109) | 浏览器设备归属持久化 | `5c8265319` |
| 6 | [#110](https://github.com/Aqr-K/MoviePilot/pull/110) | 冻结投递计划与分段恢复 | `2279b8256` |
| 7 | [#112](https://github.com/Aqr-K/MoviePilot/pull/112) | 可信 SDK 入站与交互作用域 | `42d40a328` |
| 8 | [#113](https://github.com/Aqr-K/MoviePilot/pull/113) | 浏览器投递及设备 API 装配 | `f9dddb800` |
| 9 | [#115](https://github.com/Aqr-K/MoviePilot/pull/115) | 运行装配、资源入口与业务 API | `3c03d1909` |
| 10 | [#116](https://github.com/Aqr-K/MoviePilot/pull/116) | Telegram 认证接入与分段恢复 | `0e58e9e43` |
| 11 | [#118](https://github.com/Aqr-K/MoviePilot/pull/118) | 企业微信应用、机器人及 ClawBot | `5345e92b9` |
| 12 | [#122](https://github.com/Aqr-K/MoviePilot/pull/122) | 其他内置平台的入站与投递实现 | `4fe7d0318` |
| 13 | [#123](https://github.com/Aqr-K/MoviePilot/pull/123) | 审批回执、持久投递与安全回归 | `8c87368a8` |
| 14 | [#125](https://github.com/Aqr-K/MoviePilot/pull/125) | SDK 扩展验收、架构约束与最终文档 | `6544f02a4` |

表中为实现锚点，第 14 个 PR 在该锚点后追加本次文档与索引校正；完整文档修订使用本文件所属提交或 PR 当前 HEAD。外部交付清单记录推送后实际 SHA，避免文件自引用自身提交号。

订阅和下载归属、资源与固定升级、交互上下文与可信入口、同类平台实现分别合并；授权服务、浏览器持久化、冻结投递恢复仍保留独立边界。未重排实现依赖，每组终点完整源码树等于原来已验收的阶段终点。

已由官方合入的独立测试修复保持在最终源码中。向官方移交时只提交实际剩余差异，不重复施加已存在的等价补丁。源码与测试分布不变，188 个迁移回归仍有唯一归属。

被吸收的旧 PR 与被替代的分支在新序列推送核验后退役；官方在审 PR 的分支和本序列仍在使用的前置分支继续保留。旧 PR 描述记录对应替代单元，恢复依据保存于工作区的私有引用与 Git bundle。

fork 的功能分支基线不会触发官方 v3 的完整产品 CI。PR-Agent 的占位模型凭据认证失败属于自动审查配置问题，不等于产品验证通过；移交官方时仍执行实际目标基线的门禁。

配套前端继续使用官方 PR #976；旧后端大 PR #7567 已关闭。源码审阅、正式升级、手测实例切换与发布分别执行。
