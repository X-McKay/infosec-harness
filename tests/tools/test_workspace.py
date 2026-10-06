"""The read, search and write tools keep model-authored paths as data inside the sandbox."""

import json
import subprocess
import sys

import pytest
from fakes import FakeOpenShell, final_response, make_deps, tool_returns
from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import FunctionModel

from infosec_harness.agents.investigator import build_agent
from infosec_harness.sandbox import CommandResult
from infosec_harness.tools.workspace import (
    _FILE_TOOL,
    EXCERPT_BYTES,
    MAX_FILE_BYTES,
    MAX_LINE_CHARS,
)


async def test_read_argument_is_data_in_sandbox_not_a_worker_shell():
    shell = FakeOpenShell()

    def respond(messages, info):
        if not shell.executions:
            return ModelResponse(
                parts=[ToolCallPart("read", {"path": "$(echo hostile)"}, tool_call_id="read")]
            )
        return final_response(info)

    agent = build_agent(shell, FunctionModel(respond))
    await agent.run(
        "Read",
        deps=await make_deps(shell),
    )
    _, command, _, stdin = shell.executions[0]
    assert command[5:8] == ["python", "-I", "-c"]  # after the in-sandbox timeout wrapper
    assert json.loads(stdin)["path"] == "$(echo hostile)"


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
async def test_file_tool_return_is_excerpted_on_success_and_failure(stream):
    """Review of 2026-10-06: failure stderr went into durable history unexcerpted."""
    shell = FakeOpenShell()
    native_execute = shell.execute
    large = "é" * EXCERPT_BYTES  # two bytes each, so the cut falls inside a character

    async def execute(sandbox, command, **kwargs):
        await native_execute(sandbox, command, **kwargs)
        return CommandResult(0, large, "") if stream == "stdout" else CommandResult(1, "", large)

    shell.execute = execute
    returned = []

    def respond(messages, info):
        if not shell.executions:
            return ModelResponse(parts=[ToolCallPart("read", {"path": "a.py"}, tool_call_id="r")])
        returned.extend(tool_returns(messages, "read"))
        return final_response(info)

    deps = await make_deps(shell)
    await build_agent(shell, FunctionModel(respond)).run("Read", deps=deps)
    prefix = "" if stream == "stdout" else "File tool failed (1): "
    assert returned == [prefix + "é" * (EXCERPT_BYTES // 2) + "\n[Output excerpted]"]


def run_file_tool(tmp_path, **request):
    """Run the real in-sandbox file tool under the local Python; only the sandbox repository
    path is substituted (it does not exist on a development host)."""
    root = tmp_path / "repo"
    root.mkdir(exist_ok=True)
    assert _FILE_TOOL.count("'/workspace/repo'") == 1
    script = _FILE_TOOL.replace("'/workspace/repo'", repr(str(root)))
    completed = subprocess.run(
        [sys.executable, "-I", "-c", script],
        input=json.dumps(request).encode(),
        capture_output=True,
        timeout=60,
        check=False,
    )
    stdout = completed.stdout.decode(errors="replace")
    return completed.returncode, stdout, completed.stderr.decode()


def test_file_tool_confines_paths_to_the_repository(tmp_path):
    (tmp_path / "outside.txt").write_text("secret\n")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "escape").symlink_to(tmp_path / "outside.txt")
    (root / "linked").symlink_to(tmp_path)
    (root / "inside.txt").write_text("secret is not here\n")
    relative = "Expected a relative repository path"
    for path, message in [
        ("../outside.txt", relative),
        ("sub/../../outside.txt", relative),
        (str(tmp_path / "outside.txt"), relative),
        ("escape", "Path leaves repository"),
        ("linked/outside.txt", "Path leaves repository"),
    ]:
        result = run_file_tool(tmp_path, action="read", path=path, start_line=1, end_line=5)
        assert result == (1, "", f"ValueError: {message}\n"), path
        written = run_file_tool(tmp_path, action="write", path=path, content="x")
        assert written == (1, "", f"ValueError: {message}\n"), path
    assert (tmp_path / "outside.txt").read_text() == "secret\n"
    # Search never follows a symlink out of the root, even from the root itself.
    assert run_file_tool(tmp_path, action="search", text="secret", path=".") == (
        0,
        "inside.txt:1: secret is not here\n",
        "",
    )
    assert run_file_tool(tmp_path, action="delete", path="inside.txt") == (
        1,
        "",
        "ValueError: Unknown file tool\n",
    )


def test_file_tool_reads_bounded_line_ranges(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("".join(f"line {n}\n" for n in range(1, 601)))
    (root / "latin1.txt").write_bytes(b"caf\xe9\n")
    (root / "big.txt").write_bytes(b"x" * (MAX_FILE_BYTES + 1))

    def read(path, start, end):
        return run_file_tool(tmp_path, action="read", path=path, start_line=start, end_line=end)

    assert read("a.py", 2, 3) == (0, "2: line 2\n3: line 3\n", "")
    assert read("a.py", 599, 700) == (0, "599: line 599\n600: line 600\n", "")
    assert read("a.py", 1, 501)[1].splitlines()[-1] == "501: line 501"
    for start, end in [(0, 5), (5, 4), (1, 502)]:
        assert read("a.py", start, end) == (
            1,
            "",
            "ValueError: Expected at most 501 source lines\n",
        )
    # A non-UTF-8 file is shown with replacement characters, not a traceback.
    assert read("latin1.txt", 1, 1) == (0, "1: caf�\n", "")
    assert read("big.txt", 1, 1) == (1, "", "ValueError: File exceeds read limit\n")
    code, stdout, stderr = read("missing.py", 1, 1)
    assert code == 1 and stdout == "" and stderr.startswith("FileNotFoundError: ")


def test_file_tool_output_never_exceeds_the_excerpt(tmp_path):
    """Review of 2026-10-06: one minified line could print past the native output bound,
    which ends the investigation as an unknown execution. The script cuts lines and stops
    one byte past what the worker keeps."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "min.js").write_text("var a=1;" * 40_000 + "\n")
    (root / "wide").mkdir()
    (root / "wide" / "w.txt").write_text(("needle " + "y" * 3000 + "\n") * 500)
    (root / "many").mkdir()
    (root / "many" / "m.txt").write_text("needle\n" * 150)

    code, stdout, _ = run_file_tool(
        tmp_path, action="read", path="min.js", start_line=1, end_line=1
    )
    assert code == 0
    assert stdout == "1: " + ("var a=1;" * 40_000)[:MAX_LINE_CHARS] + " [line cut]\n"

    for request in [
        dict(action="read", path="wide/w.txt", start_line=1, end_line=501),
        dict(action="search", text="needle", path="wide"),
    ]:
        code, stdout, _ = run_file_tool(tmp_path, **request)
        assert code == 0 and len(stdout.encode()) == EXCERPT_BYTES + 1
        assert all(len(line) <= MAX_LINE_CHARS + 40 for line in stdout.splitlines())

    code, stdout, _ = run_file_tool(tmp_path, action="search", text="needle", path="many")
    assert code == 0 and stdout.splitlines() == [f"many/m.txt:{n}: needle" for n in range(1, 101)]


def test_file_tool_failure_is_one_bounded_line(tmp_path):
    code, stdout, stderr = run_file_tool(
        tmp_path, action="search", text="x", path="missing/" + "d" * 20_000
    )
    assert code == 1 and stdout == ""
    assert len(stderr) <= EXCERPT_BYTES + 1 and stderr.count("\n") == 1
    assert "Traceback" not in stderr


def test_file_tool_writes_inside_the_repository(tmp_path):
    assert run_file_tool(tmp_path, action="write", path="new/dir/p.py", content="print(1)\n") == (
        0,
        "Written new/dir/p.py\n",
        "",
    )
    assert (tmp_path / "repo" / "new" / "dir" / "p.py").read_text() == "print(1)\n"
