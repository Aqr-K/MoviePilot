# -*- coding: utf-8 -*-
"""
认证服务层 —— 多步登录流程与内建因子（可碰 DB，区别于 db-free 的 ``app/core/auth``）。

  - ``flow_service`` / ``flow_engine`` / ``flow_steps``：多步登录状态机、步骤适配器与流程构建器；
  - ``builtin_factors`` ：内建 ``OtpFactor``（包装为 ``FactorStep`` 入流程）；
  - ``provisioning``    ：identity→本地用户（逐字保留 helper/sso 安全护栏）。
"""
