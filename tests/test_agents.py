"""Agent specs load under the capability allowlist and the schema is in sync."""
import json

from infosec_harness.agents import registry


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
