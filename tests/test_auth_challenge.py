# tests/test_auth_challenge.py
from app.core.auth.challenge import PromptChallenge, RedirectChallenge
def test_prompt_to_dict():
    c = PromptChallenge(step_id="otp", prompt="请输入动态码", input_kind="otp")
    assert c.kind == "prompt"
    assert c.to_dict() == {"kind":"prompt","step_id":"otp","prompt":"请输入动态码","input_kind":"otp"}
def test_redirect_to_dict():
    c = RedirectChallenge(step_id="github", provider_id="github", authorize_url="https://idp/a?x=1")
    assert c.to_dict() == {"kind":"redirect","step_id":"github","provider_id":"github","authorize_url":"https://idp/a?x=1"}
def test_frozen():
    import dataclasses, pytest
    with pytest.raises(dataclasses.FrozenInstanceError):
        PromptChallenge(step_id="otp").prompt = "x"
