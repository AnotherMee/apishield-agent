import json
import logging
import os
from typing import Literal

from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field


load_dotenv()
logger = logging.getLogger(__name__)

Priority = Literal["critical", "high", "medium", "low"]


class ReviewStep(BaseModel):
    priority: Priority
    title: str = Field(min_length=3, max_length=100)
    rationale: str = Field(min_length=10, max_length=300)
    endpoints: list[str] = Field(default_factory=list, max_length=10)


class ReviewPlan(BaseModel):
    steps: list[ReviewStep] = Field(min_length=3, max_length=7)


def deterministic_plan(endpoints: list[dict]) -> list[dict]:
    paths = [endpoint["path"] for endpoint in endpoints]
    admin_paths = sorted({path for path in paths if "admin" in path.lower()})
    object_paths = sorted({path for path in paths if "{" in path and "}" in path})
    state_changing = sorted(
        {endpoint["path"] for endpoint in endpoints if endpoint["method"] in {"POST", "PUT", "PATCH", "DELETE"}}
    )

    steps = [
        ReviewStep(
            priority="critical",
            title="Verify authentication and administrative access controls",
            rationale="Confirm that sensitive operations require authentication and enforce explicit server-side authorization.",
            endpoints=admin_paths,
        ),
        ReviewStep(
            priority="high",
            title="Review object-level authorization",
            rationale="Ensure identifiers cannot be used to access objects outside the authenticated principal's permissions.",
            endpoints=object_paths,
        ),
        ReviewStep(
            priority="high",
            title="Validate state-changing request schemas",
            rationale="Confirm server-side validation rejects unexpected fields and constrains every accepted input.",
            endpoints=state_changing,
        ),
        ReviewStep(
            priority="medium",
            title="Review data exposure and response contracts",
            rationale="Check response schemas for unnecessary sensitive fields and consistent error handling behavior.",
            endpoints=[],
        ),
        ReviewStep(
            priority="medium",
            title="Confirm abuse-prevention controls",
            rationale="Review rate limits, audit events, and operational safeguards for sensitive API workflows.",
            endpoints=[],
        ),
    ]
    return [step.model_dump() for step in steps]


def ai_plan(endpoints: list[dict]) -> tuple[list[dict] | None, str | None]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None, "OPENAI_API_KEY not configured"

    inventory = json.dumps(endpoints, separators=(",", ":"), ensure_ascii=True)
    try:
        response = OpenAI(api_key=api_key).responses.parse(
            model=os.getenv("OPENAI_MODEL", "gpt-5-mini"),
            input=[
                {
                    "role": "system",
                    "content": (
                        "You are a defensive API security reviewer. Produce a concise, prioritized review plan "
                        "based only on the supplied OpenAPI endpoint inventory. Focus on authentication, "
                        "authorization, input validation, sensitive data exposure, and abuse prevention. "
                        "Reference only endpoint paths present in the inventory. Do not provide exploit payloads, "
                        "active scanning instructions, or claims that a vulnerability is proven."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Create 3 to 7 defensive review steps for this endpoint inventory:\n{inventory}",
                },
            ],
            text_format=ReviewPlan,
        )
        parsed = response.output_parsed
        if not parsed:
            logger.warning("OpenAI planning returned no valid structured output")
            return None, "OpenAI returned invalid output"

        allowed_paths = {endpoint["path"] for endpoint in endpoints}
        steps = []
        for step in parsed.steps:
            data = step.model_dump()
            data["endpoints"] = [path for path in data["endpoints"] if path in allowed_paths]
            steps.append(data)
        return steps, None
    except Exception:
        logger.exception("OpenAI planning request failed; using deterministic fallback")
        return None, "OpenAI request failed"


def create_plan(endpoints: list[dict], use_ai: bool) -> tuple[list[dict], str, str | None]:
    if use_ai:
        plan, fallback_reason = ai_plan(endpoints)
        if plan:
            return plan, "OpenAI-assisted", None
        return deterministic_plan(endpoints), "Deterministic", fallback_reason
    return deterministic_plan(endpoints), "Deterministic", "AI-assisted planning not requested"
