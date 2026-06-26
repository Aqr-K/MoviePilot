# app/core/auth/steps.py
from typing import Any, List, Optional, Tuple
from app.core.auth.identifiers import is_valid_identifier
from app.core.auth.registry import OwnerScopedRegistry

def verify_auth_step_contract(step: Any) -> Tuple[bool, List[str]]:
    r: List[str] = []
    if not is_valid_identifier(getattr(step, "step_id", None)): r.append("step_id 非法")
    if not isinstance(getattr(step, "step_kind", None), str): r.append("step_kind 须字符串")
    p = getattr(step, "priority", None)
    if not isinstance(p, int) or isinstance(p, bool): r.append("priority 须整数")
    for m in ("applies_to", "advance"):
        if not callable(getattr(step, m, None)): r.append(f"须实现 {m}")
    return (not r), r

class AuthStepRegistry(OwnerScopedRegistry):
    def _id_of(self, i): return i.step_id
    def _validate(self, i): return verify_auth_step_contract(i)
    def _sort_key(self, i): return getattr(i, "priority", 0)
    def owner_of(self, step_id):
        with self._lock:
            e = self._registry.get(step_id); return e.owner if e else None

_R = AuthStepRegistry()
def register_auth_step(s, owner): return _R.register(s, owner)
def unregister_auth_steps(owner): _R.unregister(owner)
def get_auth_step(i): return _R.get(i)
def all_auth_steps(): return _R.all()
def auth_step_owner(i): return _R.owner_of(i)
