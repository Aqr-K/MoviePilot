# -*- coding: utf-8 -*-
"""
可插拔认证框架 —— db-free 核心。

把"主认证 provider（用什么证明身份）"与"MFA 因子（第二因子）"抽象为两条独立车道，
与既有的 SSO 重定向车道（``app/core/sso.py`` 的 ``IAuthProvider``）并列，三者均采用同一套
注册表纪律（owner-scoped、契约校验、provider/factor id 碰撞检测，见 ``registry.py``）。

本包只定义**契约与注册表**（db-free）；用户解析/建号、HTTP 端点编排、内建因子实现在更上层
（``app/service/auth`` / api），延续 ``sso.py``/``auth_bridge.py`` 不新增 core→db 边的方向。

模块：
  - ``outcome``     ：类型化结果（CredentialOutcome / MfaFactorResult / ResolvedIdentity / AuthResult）；
  - ``registry``    ：owner-scoped 注册表基类（仿 ``AuthProviderRegistry``）；
  - ``credentials`` ：主认证 provider 契约 + 注册表（``ICredentialProvider``）；
  - ``mfa_factors`` ：MFA 因子契约 + 注册表（``IMfaFactor``）。
"""
