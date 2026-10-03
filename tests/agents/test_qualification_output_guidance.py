"""Model-facing guidance preserves open schemas and strict recon scoring.

FunctionModel observes the real registry-built output tool, without testing a model's
compliance with prose or making a provider call. Live prompt effectiveness is separate.
"""
from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError
from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.registry import build_agent
from infosec_harness.domain.models import RepoProfile
from infosec_harness.evals.adapters import recon_adapter


def _profile(language: str, framework: str) -> dict[str, Any]:
    return {
        "summary": "A small service; version details belong in this summary.",
        "primary_language": language,
        "test_framework": framework,
        "test_layout": "tests/",
    }


@pytest.mark.parametrize(
    "language, framework",
    [("java", "junit5"), ("perl", "test::more"), ("unknown", "unknown"),
     ("zig", "zig-test")],
)
async def test_recon_exposes_field_guidance_without_closing_ecosystem_labels(
    tmp_path, language: str, framework: str,
) -> None:
    seen: list[dict[str, Any]] = []

    def respond(_messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        assert len(info.output_tools) == 1
        tool = info.output_tools[0]
        seen.append(tool.parameters_json_schema)
        return ModelResponse(parts=[ToolCallPart(tool.name, _profile(language, framework))])

    agent = build_agent("recon", durable=False)
    with agent.override(model=FunctionModel(respond)):
        result = await agent.run("Profile the repository.", deps=AgentDeps(repo_path=str(tmp_path)))

    assert len(seen) == 1
    properties = seen[0]["properties"]
    for field in ("summary", "primary_language", "test_framework"):
        assert properties[field]["description"] == RepoProfile.model_fields[field].description
        assert properties[field]["type"] == "string"
        assert "enum" not in properties[field]
        assert field in seen[0]["required"]
    assert result.output == RepoProfile.model_validate(_profile(language, framework))
    assert result.output.frameworks == []
    assert result.output.components == []
    assert result.output.entry_points == []


@pytest.mark.parametrize("field", ["summary", "primary_language", "test_framework", "test_layout"])
def test_recon_guidance_preserves_required_fields(field: str) -> None:
    payload = _profile("java", "junit5")
    del payload[field]
    with pytest.raises(ValidationError):
        RepoProfile.model_validate(payload)


@pytest.mark.parametrize(
    "language, framework, expected",
    [
        ("java", "junit5", "java/junit5"),
        ("perl", "test::more", "perl/test::more"),
        ("Java 17", "junit5", "java 17/junit5"),
        ("perl", "Test::More (standard Perl test framework)",
         "perl/test::more (standard perl test framework)"),
    ],
)
def test_recon_scoring_still_does_not_extract_labels_from_prose(
    tmp_path, language: str, framework: str, expected: str,
) -> None:
    # The independent scorer remains strict; guidance must repair model output rather
    # than changing the accepted answer to accommodate explanatory text in label fields.
    _, _, _, predict, _ = recon_adapter({"repo": str(tmp_path), "expected": "unused"})
    assert predict(RepoProfile.model_validate(_profile(language, framework))) == expected
