# -*- coding: utf-8 -*-
"""
认证标识符的集中校验与派生（PR8 收口）。

把原本散落在 ``sso.py`` / ``credentials.py`` / ``mfa_factors.py`` / ``helper/sso.py`` /
``provisioning.py`` 五处、逐字重复的正则与命名前缀收敛到唯一来源，杜绝拷贝漂移。

约定（与历史完全一致，仅去重不改语义）：
  - ``IDENTIFIER_RE``：provider_id / factor_id —— 字母数字与连字符，1–32 位。禁下划线等分隔符，
    因 provider_id 会进入本地用户名 ``sso_{provider_id}_{subject}`` 与回调 URL 路径片段，
    禁分隔符可数学上杜绝跨提供方撞名与路径注入。
  - ``SUBJECT_RE``：身份主键 subject —— 字母数字与 ``. _ -``，最长 64，首尾为字母数字。
  - ``CODE_RE``：OAuth 授权码 —— 字母数字与 ``_ -``，1–256 位（边界输入校验，防注入下游/日志）。
  - ``USERNAME_PREFIX``：外部托管账号本地用户名前缀（与本地账号命名空间隔离）。
"""
import re
from typing import Any

IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9\-]{1,32}$")
SUBJECT_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._\-]{0,62}[A-Za-z0-9])?$")
CODE_RE = re.compile(r"^[A-Za-z0-9_\-]{1,256}$")
USERNAME_PREFIX = "sso_"


def is_valid_identifier(value: Any) -> bool:
    """provider_id / factor_id 是否合法。"""
    return isinstance(value, str) and bool(IDENTIFIER_RE.match(value))


def is_valid_subject(value: Any) -> bool:
    """身份 subject 是否合法。"""
    return isinstance(value, str) and bool(SUBJECT_RE.match(value))


def is_valid_code(value: Any) -> bool:
    """OAuth 授权码是否合法。"""
    return isinstance(value, str) and bool(CODE_RE.match(value))


def derive_local_username(provider_id: str, subject: str) -> str:
    """由稳定 ``(provider_id, subject)`` 派生本地用户名。

    provider_id 不含分隔符（核心契约保证），故该映射单射、无跨提供方撞名。
    """
    return f"{USERNAME_PREFIX}{provider_id}_{subject}"
