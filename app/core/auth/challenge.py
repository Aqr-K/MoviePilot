# app/core/auth/challenge.py
# -*- coding: utf-8 -*-
"""多态认证挑战 ADT（db-free，frozen）。机制差异收敛于此；本期 Prompt/Redirect 两变体。"""
from dataclasses import dataclass
from typing import Any, ClassVar, Dict

@dataclass(frozen=True)
class Challenge:
    step_id: str
    kind: ClassVar[str] = ""
    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "step_id": self.step_id}

@dataclass(frozen=True)
class PromptChallenge(Challenge):
    prompt: str = ""
    input_kind: str = "text"  # otp | password | text
    kind: ClassVar[str] = "prompt"
    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict(); d.update(prompt=self.prompt, input_kind=self.input_kind); return d

@dataclass(frozen=True)
class RedirectChallenge(Challenge):
    provider_id: str = ""
    authorize_url: str = ""
    kind: ClassVar[str] = "redirect"
    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict(); d.update(provider_id=self.provider_id, authorize_url=self.authorize_url); return d
