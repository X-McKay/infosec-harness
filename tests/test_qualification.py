from types import SimpleNamespace

from infosec_harness.evals import qualification


async def test_runtime_qualification_uses_actual_directory_upload_contract(tmp_path, monkeypatch):
    config = tmp_path / "runtime.json"
    config.write_text("{}")
    qualification.get_settings().openshell_config = config
    uploads = []
    closes = []
    source_bytes = b"native-roundtrip\n"

    class Runtime:
        async def create(self, run_id, *, profile):
            return SimpleNamespace(id=profile)

        async def upload(self, sandbox, source, destination):
            assert source.is_dir()
            assert (source / "input.txt").read_bytes() == source_bytes
            uploads.append((sandbox.id, destination))

        async def execute(self, sandbox, command, **kwargs):
            assert "/workspace/qualification/input.txt" in command[-1]
            return SimpleNamespace(
                exit_code=0, stdout=source_bytes.decode(), output_truncated=False
            )

        async def close(self, sandbox):
            closes.append(sandbox.id)

        async def close_run(self, run_id):
            closes.append(run_id)

    monkeypatch.setattr(qualification.OpenShellConfig, "load", lambda path: None)
    monkeypatch.setattr(qualification, "OpenShell", lambda config: Runtime())
    result = await qualification.qualify_runtime(tmp_path / "report.json")
    assert result["status"] == "passed"
    assert uploads == [
        ("workspace", "/workspace/qualification"),
        ("probe", "/workspace/qualification"),
    ]
    assert closes[:4] == ["workspace", "workspace", "probe", "probe"]
    assert result["model_calls"] == 0
