# 内置平台协议实现

各模块通过既有宿主清单声明 provider 与兼容传输类型；连接的身份空间和实际入口信任由宿主另外绑定。平台只产生规范主体、会话、地址和能力事实，不批准成员或授予业务操作。

| provider | 兼容传输类型 | 交互入口 | 协议 owner |
| --- | --- | --- | --- |
| `apppush` | `AppPush` | 无 | [平台实现](../../app/modules/apppush/channel.py) |
| `dingtalk` | `钉钉` | 无 | [平台实现](../../app/modules/dingtalk/channel.py) |
| `discord` | `Discord` | 有 | [平台实现](../../app/modules/discord/channel.py) |
| `feishu` | `飞书` | 有 | [平台实现](../../app/modules/feishu/channel.py) |
| `qqbot` | `QQ` | 有 | [平台实现](../../app/modules/qqbot/channel.py) |
| `slack` | `Slack` | 有 | [平台实现](../../app/modules/slack/channel.py) |
| `synologychat` | `SynologyChat` | 有 | [平台实现](../../app/modules/synologychat/channel.py) |
| `telegram` | `Telegram` | 有 | [平台实现](../../app/modules/telegram/channel.py) |
| `vocechat` | `VoceChat` | 有 | [平台实现](../../app/modules/vocechat/channel.py) |
| `webpush` | `WebPush` | 无 | [平台实现](../../app/modules/webpush/channel.py) |
| `wechat` | `微信` | 有 | [平台实现](../../app/modules/wechat/channel.py) |
| `wechatclawbot` | `微信ClawBot` | 有 | [平台实现](../../app/modules/wechatclawbot/channel.py) |

凭据约束、专属表单、身份诊断和特殊附件分段归各平台实现；公共授权、规则、受众限制、Outbox 与重试继续由宿主独立执行。

同一目录保留全部 12 个内置平台。第三方网关、缺少认证材料的连接按平台能力限制规则选项；能力声明本身不是认证证明。真实企业微信验收继续跳过，回归使用隔离配置和模拟协议。
