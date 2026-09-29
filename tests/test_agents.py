"""Agent specs load under the capability allowlist and the schema is in sync."""
import json

from infosec_harness.agents import registry
from infosec_harness.resources import agents_dir, skills_dir


def test_all_specs_valid():
    assert registry.validate_all() == []


def test_bindings_match_specs_on_disk():
    assert set(registry.AGENT_BINDINGS) == registry.spec_names_on_disk()


def test_config_hashes_are_stable_and_distinct():
    hashes = registry.agent_config_hashes()
    assert len(set(hashes.values())) == len(hashes)
    assert registry.agent_config_hashes() == hashes  # cached, deterministic


def test_committed_schema_is_current():
    on_disk = json.loads((registry.get_settings().agents_dir / "agent_schema.json").read_text())
    assert on_disk == registry.json_schema(), "run `just agents-schema` to regenerate"


# --- OpenAI-spec single-system-message compatibility (see agents/models.py) ---

def test_max_tokens_floor_raises_small_budgets_and_leaves_large_ones():
    """A reasoning endpoint spends thinking inside max_tokens; the floor only raises."""
    from infosec_harness.agents.models import _apply_max_tokens_floor

    assert _apply_max_tokens_floor({"max_tokens": 3000}, 16000) == {"max_tokens": 16000}
    assert _apply_max_tokens_floor({"max_tokens": 32000}, 16000) == {"max_tokens": 32000}
    assert _apply_max_tokens_floor({"max_tokens": 3000}, 0) == {"max_tokens": 3000}
    assert _apply_max_tokens_floor(None, 0) is None


def test_max_tokens_floor_preserves_other_settings():
    from infosec_harness.agents.models import _apply_max_tokens_floor

    out = _apply_max_tokens_floor({"max_tokens": 10, "temperature": 0.0}, 99)
    assert out == {"max_tokens": 99, "temperature": 0.0}


def test_the_token_floor_reaches_the_setting_pydantic_ai_reports(monkeypatch):
    """The floor must land on the agent's `model_settings`, not only on the wire payload.

    pydantic-ai copies `model_settings['max_tokens']` into `GraphAgentState.last_max_tokens`
    while building the request, *before* it calls `Model.prepare_request`, and that copy is
    the number in "Model token limit (N) exceeded before any response was generated". With
    the floor applied only in `prepare_request`, a live Java-corpus `probe-planner` call that
    really had — and spent — a 16000-token cap (`out=16000 finish=length` on the wire) raised
    `Model token limit (6000) exceeded`: the diagnostic named the superseded spec value and
    its accounting disagreed with the request.

    Applying it in both places also makes them provably agree: once the setting carries the
    floor, the payload-side floor is a no-op.
    """
    from infosec_harness.agents.models import (
        _apply_max_tokens_floor,
        load_models_config,
        max_tokens_floor,
    )

    monkeypatch.setenv("HARNESS_MODEL_BACKEND", "gateway")
    floor = load_models_config().backends["gateway"].min_max_tokens
    assert floor, "this test needs a backend that declares a per-call floor"
    assert max_tokens_floor("probe-planner") == floor

    raised = 0
    for name in registry.AGENT_BINDINGS:
        declared = (registry.load_spec(name).model_settings or {}).get("max_tokens") or 0
        effective = registry.build_agent(name, durable=False).model_settings or {}
        assert effective.get("max_tokens") == max(declared, floor), (
            f"{name}: spec declares {declared} and the backend floor is {floor}, but the "
            f"agent pydantic-ai will report on carries {effective.get('max_tokens')}"
        )
        # The payload-side floor is now redundant, which is what "they agree" means.
        assert _apply_max_tokens_floor(effective, floor) == effective, name
        raised += declared < floor
    assert raised, "no spec sits below the floor, so this test would pass vacuously"


def test_the_token_floor_is_inert_where_thinking_has_its_own_budget(monkeypatch):
    """Bedrock budgets thinking separately, so the floor must not touch those specs."""
    monkeypatch.setenv("HARNESS_MODEL_BACKEND", "bedrock")
    from infosec_harness.agents.models import max_tokens_floor

    assert max_tokens_floor("probe-planner") == 0
    for name in registry.AGENT_BINDINGS:
        declared = (registry.load_spec(name).model_settings or {}).get("max_tokens")
        assert (registry.build_agent(name, durable=False).model_settings or {}).get(
            "max_tokens") == declared, name


def test_merge_leading_system_messages_collapses_the_prefix():
    from infosec_harness.agents.models import _merge_leading_system_messages

    merged = _merge_leading_system_messages([
        {"role": "system", "content": "instructions"},
        {"role": "system", "content": "deferred capabilities"},
        {"role": "user", "content": "task"},
    ])
    assert merged == [
        {"role": "system", "content": "instructions\n\ndeferred capabilities"},
        {"role": "user", "content": "task"},
    ]


def test_merge_leading_system_messages_leaves_conforming_requests_alone():
    from infosec_harness.agents.models import _merge_leading_system_messages

    for messages in ([{"role": "system", "content": "s"}, {"role": "user", "content": "u"}],
                     [{"role": "user", "content": "u"}]):
        assert _merge_leading_system_messages(list(messages)) == messages


def test_merge_does_not_touch_a_later_system_message():
    """Only the leading run is collapsed; a mid-conversation system turn stays put."""
    from infosec_harness.agents.models import _merge_leading_system_messages

    messages = [{"role": "system", "content": "a"}, {"role": "system", "content": "b"},
                {"role": "user", "content": "u"}, {"role": "system", "content": "late"}]
    assert _merge_leading_system_messages(messages) == [
        {"role": "system", "content": "a\n\nb"},
        {"role": "user", "content": "u"},
        {"role": "system", "content": "late"},
    ]


def test_openai_backends_are_configured_for_single_system_endpoints():
    from infosec_harness.agents.models import load_models_config

    cfg = load_models_config()
    for name, backend in cfg.backends.items():
        if backend.kind == "openai_compatible":
            assert backend.merge_system_messages, f"{name} would 400 on single-system endpoints"


def test_gateway_catalog_only_names_ids_the_endpoint_serves():
    """Every tier must resolve to a real id; a typo here fails at the first live call."""
    from infosec_harness.agents.models import load_models_config

    cfg = load_models_config()
    for tier, per_backend in cfg.model_catalog.items():
        assert per_backend.get("gateway"), f"tier {tier} has no gateway model id"


def test_openai_backends_ride_out_transient_upstream_failures():
    """One 502 from a self-hosted endpoint must not kill a whole batch run."""
    from infosec_harness.agents.models import load_models_config

    cfg = load_models_config()
    for name, backend in cfg.backends.items():
        if backend.kind == "openai_compatible":
            assert backend.max_retries >= 3, f"{name} retries too few times to be useful"


def test_no_spec_asks_for_more_thinking_than_its_own_token_ceiling_allows():
    """Anthropic counts thinking *inside* `max_tokens`, so `budget_tokens >= max_tokens` is
    rejected by the API — and the answer gets whatever is left, so equality leaves zero.

    Latent rather than broken today: `anthropic.claude-sonnet-5` and `opus-5` report
    `bedrock_supports_adaptive_thinking`, so `budget_tokens` is never sent. But `claude-haiku-4-5`
    does not, and it is what the `fast-v1` model policy resolves to — so routing any offending
    agent to `fast-v1` would 400 on every call. Five specs were in that state (build-repair,
    context, env-planner, partial-build, verdict), each declaring `medium` (10000) against a
    4000-8000 ceiling.

    Asserts the derivation, not the numbers: a spec may declare any thinking level, but its
    ceiling must leave a real answer behind it.
    """

    import yaml
    from pydantic_ai.profiles.anthropic import ANTHROPIC_THINKING_BUDGET_MAP

    # Below this an answer is not meaningfully expressible, so equality-plus-epsilon is not
    # enough to call the spec coherent.
    MIN_ANSWER_TOKENS = 1024
    checked = 0
    for path in sorted(agents_dir().glob("*/agent.yaml")):
        settings = yaml.safe_load(path.read_text()).get("model_settings") or {}
        max_tokens, thinking = settings.get("max_tokens"), settings.get("thinking")
        level = thinking.get("effort") if isinstance(thinking, dict) else thinking
        budget = ANTHROPIC_THINKING_BUDGET_MAP.get(level) if level is not None else None
        if budget is None or max_tokens is None:
            continue
        checked += 1
        assert max_tokens - budget >= MIN_ANSWER_TOKENS, (
            f"{path.parent.name}: thinking={level!r} reserves {budget} of a {max_tokens}-token "
            f"ceiling, leaving {max_tokens - budget} for the answer. Anthropic counts thinking "
            f"inside max_tokens, so raise max_tokens to at least {budget + MIN_ANSWER_TOKENS} "
            f"(the answer share this agent needs, plus {budget}) or lower the thinking level."
        )
    assert checked >= 10, f"only {checked} specs declared a thinking level; the schema changed"


def test_the_probe_writing_agents_are_told_about_the_sink_returned_marker():
    """The marker count in a prompt must not drift from the protocol it points at.

    `probe-author` and `probe-repair` both said "the two markers" long after the protocol
    defined three. The sink-returned marker was added later, as the fix for a measured false
    negative on javascript-cmdi-vulnerable: the precondition marker prints *before* the sink
    call, so without a second marker after it, a probe that threw mid-call is indistinguishable
    from one the code resisted. An agent told there are two markers can silently drop the one
    that prevents this system's costliest error.

    Deliberately checks the prompts rather than the skill: the skill was always correct, and it
    is the prompt that told them otherwise.
    """

    import yaml

    for name in ("probe-author", "probe-repair"):
        spec = yaml.safe_load((agents_dir() / name / "agent.yaml").read_text())
        text = " ".join(spec["instructions"]).lower()
        assert "two markers" not in text, (
            f"{name}: says 'two markers', but probe-oracle-protocol defines three "
            "(precondition, sink-returned, oracle)"
        )
        assert "sink-returned" in text or "sink_returned" in text, (
            f"{name} writes probe source but is never told to emit the sink-returned marker; "
            "without it a probe that threw mid-call reads as a clean negative"
        )


def test_the_protocol_skill_still_defines_exactly_the_three_markers_the_prompts_promise():
    """Guards the other direction: if the protocol ever changes its marker set, the test above
    stops meaning anything, so tie the prompts' promise to the skill's own text."""

    protocol = (skills_dir() / "probe-oracle-protocol" / "SKILL.md").read_text()
    assert "## The three markers" in protocol
    for marker in ("HARNESS_PRECONDITION::", "HARNESS_SINK_RETURNED::", "HARNESS_ORACLE::"):
        assert marker in protocol, f"{marker} missing from the protocol skill"
