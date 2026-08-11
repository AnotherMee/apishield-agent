from types import SimpleNamespace

from app.agents import planner


ENDPOINTS = [
    {
        "method": "GET",
        "path": "/admin/users",
        "operation_id": "listUsers",
        "auth_required": False,
        "parameters": [],
    }
]


def test_create_plan_uses_deterministic_mode_when_ai_is_disabled(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    plan, mode, reason = planner.create_plan(ENDPOINTS, use_ai=False)

    assert mode == "Deterministic"
    assert reason == "AI-assisted planning not requested"
    assert 3 <= len(plan) <= 7


def test_create_plan_falls_back_without_api_key(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    plan, mode, reason = planner.create_plan(ENDPOINTS, use_ai=True)

    assert mode == "Deterministic"
    assert reason == "OPENAI_API_KEY not configured"
    assert 3 <= len(plan) <= 7
    assert set(plan[0]) == {"priority", "title", "rationale", "endpoints"}
    assert plan[0]["endpoints"] == ["/admin/users"]


def test_create_plan_uses_structured_openai_output(monkeypatch) -> None:
    captured = {}
    structured = planner.ReviewPlan(
        steps=[
            planner.ReviewStep(
                priority="critical",
                title="Review administrative authentication",
                rationale="The administrative route declares no authentication requirement.",
                endpoints=["/admin/users", "/invented"],
            ),
            planner.ReviewStep(
                priority="high",
                title="Confirm authorization policy",
                rationale="Administrative access needs an explicit server-side authorization policy.",
                endpoints=["/admin/users"],
            ),
            planner.ReviewStep(
                priority="medium",
                title="Review audit coverage",
                rationale="Sensitive administrative activity should create useful security audit events.",
                endpoints=["/admin/users"],
            ),
        ]
    )

    class FakeResponses:
        def parse(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(output_parsed=structured)

    class FakeOpenAI:
        def __init__(self, api_key):
            captured["api_key"] = api_key
            self.responses = FakeResponses()

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "test-model")
    monkeypatch.setattr(planner, "OpenAI", FakeOpenAI)

    plan, mode, reason = planner.create_plan(ENDPOINTS, use_ai=True)

    assert mode == "OpenAI-assisted"
    assert reason is None
    assert captured["api_key"] == "test-key"
    assert captured["model"] == "test-model"
    assert captured["text_format"] is planner.ReviewPlan
    assert plan[0]["priority"] == "critical"
    assert plan[0]["endpoints"] == ["/admin/users"]


def test_create_plan_falls_back_when_openai_request_fails(monkeypatch, caplog) -> None:
    class FailingResponses:
        def parse(self, **kwargs):
            raise RuntimeError("mock OpenAI outage")

    class FailingOpenAI:
        def __init__(self, api_key):
            self.responses = FailingResponses()

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(planner, "OpenAI", FailingOpenAI)

    plan, mode, reason = planner.create_plan(ENDPOINTS, use_ai=True)

    assert plan
    assert mode == "Deterministic"
    assert reason == "OpenAI request failed"
    assert "mock OpenAI outage" in caplog.text


def test_create_plan_falls_back_for_invalid_openai_output(monkeypatch) -> None:
    class EmptyResponses:
        def parse(self, **kwargs):
            return SimpleNamespace(output_parsed=None)

    class EmptyOpenAI:
        def __init__(self, api_key):
            self.responses = EmptyResponses()

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(planner, "OpenAI", EmptyOpenAI)

    _, mode, reason = planner.create_plan(ENDPOINTS, use_ai=True)

    assert mode == "Deterministic"
    assert reason == "OpenAI returned invalid output"
