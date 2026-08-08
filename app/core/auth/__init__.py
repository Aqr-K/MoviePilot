# -*- coding: utf-8 -*-
"""
可插拔认证框架 —— db-free 核心。

把主认证、MFA 第二因子与 SSO 重定向统一为一条「认证步骤」抽象（``IAuthStep``，见 ``flow.py`` /
``steps.py``）；SSO 重定向提供方契约（``app/core/auth/redirect.py`` 的 ``IAuthProvider``）作为重定向步的
底层构件保留。所有注册表均采用同一套纪律（owner-scoped、契约校验、id 碰撞检测，见 ``registry.py``）。

本包只定义**契约与注册表**（db-free）；用户解析/建号、HTTP 端点编排、内建因子实现在更上层
（``app/service/auth`` / api），本包不引入 core→db 的依赖方向。

模块：
  - ``types``       ：共享值类型（CredentialRequest / MfaUserRef / MfaSubmission / MfaChallengeHint）；
  - ``outcome``     ：类型化结果（CredentialOutcome / MfaFactorResult / ResolvedIdentity / AuthResult）；
  - ``registry``    ：owner-scoped 注册表基类；
  - ``flow`` / ``steps`` / ``flow_registry``：认证步骤契约（``IAuthStep``）、步骤注册表与流程规格注册表；
  - ``redirect``    ：SSO 重定向提供方契约 + 注册表（``IAuthProvider``）。
"""
