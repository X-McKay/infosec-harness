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
