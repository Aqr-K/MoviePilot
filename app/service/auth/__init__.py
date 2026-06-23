# -*- coding: utf-8 -*-
"""
认证服务层 —— 编排与内建因子（可碰 DB，区别于 db-free 的 ``app/core/auth``）。

  - ``orchestrator``    ：``evaluate_mfa()``（PR2）、``resolve_identity()``（PR4）；
  - ``builtin_factors`` ：内建 ``OtpFactor`` / ``PasskeyFactor``（1:1 复现现 ``_verify_mfa``）；
  - ``provisioning``    ：identity→本地用户（PR4，逐字保留 helper/sso 安全护栏）。
"""
