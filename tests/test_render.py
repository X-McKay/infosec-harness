from pydantic_ai.messages import CachePoint

from infosec_harness.agents.render import prompt_text, render_prompt, repo_context_block
from infosec_harness.domain.models import RepoProfile, StackFingerprint


def _stack():
    return StackFingerprint(languages={"python": 2}, test_frameworks=["pytest"])


def test_render_is_byte_stable():
    a = render_prompt("Do it.", {"finding": {"cwe": "CWE-89"}}, stack=_stack())
    b = render_prompt("Do it.", {"finding": {"cwe": "CWE-89"}}, stack=_stack())
    assert prompt_text(a) == prompt_text(b)


def test_cache_point_after_repo_context():
    content = render_prompt("t", {"x": "1"}, stack=_stack())
    assert any(isinstance(c, CachePoint) for c in content)
    # repo context (stable) comes before the cache point; task input after it
    idx = next(i for i, c in enumerate(content) if isinstance(c, CachePoint))
    assert "Repository context" in content[0]
    assert any("Task input" in c for c in content[idx + 1:] if isinstance(c, str))


def test_volatile_fields_excluded():
    prof = RepoProfile(summary="s", primary_language="python", test_framework="pytest", test_layout="tests/")
    assert "python" in repo_context_block(_stack(), prof)
    # volatile keys never appear even if present in a dict payload
    content = render_prompt("t", {"snapshot": {"path": "/abs/secret", "content_hash": "h"}})
    assert "/abs/secret" not in prompt_text(content)
    assert "content_hash" in prompt_text(content)
