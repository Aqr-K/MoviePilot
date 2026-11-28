# 后端 PR 提交顺序

代码来源固定为 `610cc4a1b7d6720634312b57d7d1aad5fe1c8df8`，产品目录树为 `6f239ace264c5e555501ef2912987b2a813d0f3b`。准确提交、分支、依赖与验收结果见 [源码索引](source-index.json)。

独立官方前置可分别审阅：[#7638](https://github.com/jxxghp/MoviePilot/pull/7638)、[#7639](https://github.com/jxxghp/MoviePilot/pull/7639)、[#7640](https://github.com/jxxghp/MoviePilot/pull/7640)、[#7642](https://github.com/jxxghp/MoviePilot/pull/7642)、[#7643](https://github.com/jxxghp/MoviePilot/pull/7643)。其中 #7638 已由官方合入；其余状态以对应 PR 的当前检查为准。

依赖单元在 fork 逐级建立小 PR。官方前置合入后，从下表第一项开始，在新的官方目标基线上逐个移交；不要把聚合基础分支作为一次大变更合入。

| 顺序 | PR | 职责 | 当前提交 |
| --- | --- | --- | --- |
| 4 | [#102](https://github.com/Aqr-K/MoviePilot/pull/102) | platform-contract | `df6771f4a` |
| 5 | [#103](https://github.com/Aqr-K/MoviePilot/pull/103) | platform-facts | `7a43aa3aa` |
| 6 | [#104](https://github.com/Aqr-K/MoviePilot/pull/104) | resource-settings | `089f2c292` |
| 7 | [#105](https://github.com/Aqr-K/MoviePilot/pull/105) | offline-migration | `46632db1d` |
| 8 | [#106](https://github.com/Aqr-K/MoviePilot/pull/106) | authorization | `10566fb89` |
| 9 | [#107](https://github.com/Aqr-K/MoviePilot/pull/107) | subscription-ownership | `cb14f801e` |
| 10 | [#108](https://github.com/Aqr-K/MoviePilot/pull/108) | download-ownership | `40a3ab422` |
| 11 | [#109](https://github.com/Aqr-K/MoviePilot/pull/109) | webpush-persistence | `49f0c8713` |
| 12 | [#110](https://github.com/Aqr-K/MoviePilot/pull/110) | delivery-progress | `f61637e0d` |
| 13 | [#111](https://github.com/Aqr-K/MoviePilot/pull/111) | interaction-context | `bc0e8531a` |
| 14 | [#112](https://github.com/Aqr-K/MoviePilot/pull/112) | host-ingress | `c5cb0d0b1` |
| 15 | [#113](https://github.com/Aqr-K/MoviePilot/pull/113) | webpush-delivery | `5371f332c` |
| 16 | [#114](https://github.com/Aqr-K/MoviePilot/pull/114) | runtime-routing | `c7402f1fd` |
| 17 | [#115](https://github.com/Aqr-K/MoviePilot/pull/115) | owned-business-api | `c27065dd8` |
| 18 | [#116](https://github.com/Aqr-K/MoviePilot/pull/116) | telegram | `19fd27f86` |
| 19 | [#117](https://github.com/Aqr-K/MoviePilot/pull/117) | wechat | `410b7f296` |
| 20 | [#118](https://github.com/Aqr-K/MoviePilot/pull/118) | clawbot | `caf943f2f` |
| 21 | [#119](https://github.com/Aqr-K/MoviePilot/pull/119) | slack | `7fbb54d21` |
| 22 | [#120](https://github.com/Aqr-K/MoviePilot/pull/120) | workspace-sdk | `536d835e9` |
| 23 | [#121](https://github.com/Aqr-K/MoviePilot/pull/121) | qq-voce | `00729d20e` |
| 24 | [#122](https://github.com/Aqr-K/MoviePilot/pull/122) | callback-delivery | `b4a0a0f6c` |
| 25 | [#123](https://github.com/Aqr-K/MoviePilot/pull/123) | authorization-outbox | `22a761d41` |
| 26 | [#124](https://github.com/Aqr-K/MoviePilot/pull/124) | extension-boundaries | `610cc4a1b` |

第 12 单元包含独立的测试隔离提交（官方 #7642），第 17、19 单元分别包含终端单读者与多读者管道夹具修复（官方 #7643）。若官方已合入相应独立修复，移交时跳过其等价提交，只保留本单元功能提交；精确提交列表见索引。第 4 单元另有独立的导入排序修正，应与该单元一起移交。

fork 的功能分支基线不会触发官方 v3 的完整 CI；本地证据与远端状态分别记录。PR-Agent 的占位模型凭据认证失败属于该自动审查配置，不等于产品测试结果。向官方移交时仍执行实际目标基线的完整门禁，不能以本索引绕过保护。

配套前端保持原 PR #976。原后端大 PR #7567 由这套序列替代；实际部署、正式升级及手测实例切换独立执行。
