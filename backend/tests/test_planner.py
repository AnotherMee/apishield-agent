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


def test_create_plan_falls_back_without_api_key(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    plan, mode = planner.create_plan(ENDPOINTS, use_ai=True)

    assert mode == "Deterministic"
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

    plan, mode = planner.create_plan(ENDPOINTS, use_ai=True)

    assert mode == "OpenAI-assisted"
    assert captured["api_key"] == "test-key"
    assert captured["model"] == "test-model"
    assert captured["text_format"] is planner.ReviewPlan
    assert plan[0]["priority"] == "critical"
    assert plan[0]["endpoints"] == ["/admin/users"]
