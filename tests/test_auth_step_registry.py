from app.core.auth.steps import register_auth_step, unregister_auth_steps, get_auth_step, auth_step_owner, verify_auth_step_contract
class _S:
    step_id="ldap"; step_kind="directory"; priority=10
    def applies_to(self, c): return True
    def advance(self, c, s): ...
def test_register_owner():
    assert register_auth_step(_S(), owner="plg")[0]
    assert get_auth_step("ldap") and auth_step_owner("ldap") == "plg"
    unregister_auth_steps("plg"); assert get_auth_step("ldap") is None
def test_contract_rejects(): assert not verify_auth_step_contract(object())[0]
