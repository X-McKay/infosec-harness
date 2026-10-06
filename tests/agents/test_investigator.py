"""The investigator's verdict validator: bounded feedback that never re-dispatches tools."""

import json
from types import SimpleNamespace

import pytest
from fakes import FakeOpenShell, final_response, make_deps, retry_feedback, tool_returns
from pydantic_ai.messages import ModelRequest, ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel

from infosec_harness.agents.investigator import build_agent
from infosec_harness.sandbox import CommandResult


@pytest.mark.parametrize("definitive", [False, True])
async def test_output_feedback_repairs_exact_id_or_failed_probe_without_reexecuting(definitive):

    shell = FakeOpenShell()
    calls = 0

    def respond(messages, info):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "execute", {"command": "python probe.py"}, tool_call_id="receipt-suffix"
                    )
                ]
            )
        if calls == 2:
            response = final_response(
                info, evidence_ids=["execute:1" if not definitive else "execute:1:receipt-suffix"]
            )
            if definitive:
                response.parts[0].args["label"] = "potentially_exploitable"
            return response
        feedback = retry_feedback(messages)
        assert feedback
        assert (
            "cannot support a definitive verdict" if definitive else "exact full Evidence.id"
        ) in feedback[-1]
        return final_response(info, evidence_ids=["execute:1:receipt-suffix"])

    result = await build_agent(shell, FunctionModel(respond)).run(
        "Inspect",
        deps=await make_deps(shell),
    )
    assert result.output.label == "inconclusive"
    assert calls == 3
    assert len(shell.executions) == 1


async def test_validator_lets_a_newer_cited_probe_supersede_an_older_flawed_one():
    """Live case 'unreachable' (2026-10-05): an early buggy probe reported vulnerability_observed
    true, three corrected later probes reported false, and the verdict could never be admitted.
    The agent may disown only probes older than the cited one, and must name them."""
    from pydantic_ai import ModelRetry

    from infosec_harness.agents.investigator import validate_verdict
    from infosec_harness.contracts import Evidence, Verdict

    def probe(identity, observed):
        return Evidence(
            id=identity, kind="probe", command="python probe.py", exit_code=0,
            source_digest="digest", sandbox_id="offline",
            observations=dict(workspace_digest="w", origin="self_reported", source_verified=True,
                              target_reached=True, oracle_valid=True, positive_control=True,
                              negative_control=True, vulnerability_observed=observed),
        )

    flawed, corrected, later = probe("probe:6:a", True), probe("probe:9:b", False), probe("probe:12:c", True)
    ctx = SimpleNamespace(
        deps=SimpleNamespace(source_digest="digest"),
        messages=[ModelRequest(parts=[
            ToolReturnPart("run_probe", item.model_dump(), tool_call_id=item.id.split(":")[-1])
            for item in (flawed, corrected, later)])],
    )
    base = dict(label="likely_not_exploitable", summary="fixed query, flawed probe explained",
                evidence_ids=[corrected.id], citations=[dict(path="app.py", start_line=1, end_line=1)])
    # A later contrary probe blocks the verdict even when listed as superseded.
    with pytest.raises(ModelRetry, match="probe:12:c contradict.*cannot be superseded"):
        await validate_verdict(ctx, Verdict(**base, superseded_evidence_ids=[flawed.id, later.id]))
    ctx.messages[0].parts.pop()  # without the later probe, the older flawed one can be superseded
    with pytest.raises(ModelRetry, match="probe:6:a contradict"):
        await validate_verdict(ctx, Verdict(**base))
    accepted = Verdict(**base, superseded_evidence_ids=[flawed.id])
    assert await validate_verdict(ctx, accepted) == accepted
    with pytest.raises(ModelRetry, match="exact full Evidence.id"):
        await validate_verdict(ctx, Verdict(**base, superseded_evidence_ids=["probe:1:unknown"]))


@pytest.mark.parametrize(
    "failure",
    [
        None,
        "failed",
        "truncated",
        "unverified",
        "wrong-source",
        "controls",
        "target_reached",
        "oracle_valid",
        "positive_control",
        "contrary",
    ],
)
async def test_verdict_validator_requires_complete_matching_offline_evidence(failure):
    from pydantic_ai import ModelRetry

    from infosec_harness.agents.investigator import validate_verdict
    from infosec_harness.contracts import Evidence, Verdict

    observations = dict(
        workspace_digest="workspace",
        origin="self_reported",
        source_verified=True,
        target_reached=True,
        oracle_valid=True,
        positive_control=True,
        negative_control=True,
        vulnerability_observed=True,
    )
    if failure == "unverified":
        observations["source_verified"] = False
    if failure == "controls":
        observations["negative_control"] = False
    if failure in ("target_reached", "oracle_valid", "positive_control"):
        observations[failure] = False
    if failure == "contrary":
        observations["vulnerability_observed"] = False
    evidence = Evidence(
        id="probe:6:full-suffix",
        kind="probe",
        command="python probe.py",
        exit_code=1 if failure == "failed" else 0,
        output_truncated=failure == "truncated",
        source_digest="other" if failure == "wrong-source" else "digest",
        sandbox_id="offline",
        observations=observations,
    )
    ctx = SimpleNamespace(
        deps=SimpleNamespace(source_digest="digest"),
        messages=[
            ModelRequest(
                parts=[
                    ToolReturnPart("run_probe", evidence.model_dump(), tool_call_id="full-suffix")
                ]
            )
        ],
    )
    verdict = Verdict(
        label="potentially_exploitable",
        summary="Source-supported path",
        evidence_ids=[evidence.id],
        citations=[dict(path="sink.py", start_line=1, end_line=1)],
    )
    if failure == "target_reached":
        # A malformed exploratory citation must not hide the false target claim.
        exploratory = evidence.model_copy(update={"id": "probe:earlier", "observations": {}})
        ctx.messages[0].parts.append(
            ToolReturnPart("run_probe", exploratory.model_dump(), tool_call_id="earlier")
        )
        verdict.evidence_ids.append(exploratory.id)
    if failure:
        # Feedback must name the exact failing condition, not a generic rule restatement.
        match = {
            "failed": "is not a complete probe: exit code 1",
            "truncated": "output was truncated",
            "unverified": "is not source-verified",
            "wrong-source": "No run_probe evidence cited",
            "controls": "negative_control=false",
            "target_reached": "target_reached=false; target_reached is true when the real target",
            "oracle_valid": "oracle_valid=false",
            "positive_control": "positive_control=false",
            "contrary": "contradict potentially_exploitable",
        }[failure]
        with pytest.raises(ModelRetry, match=match):
            await validate_verdict(ctx, verdict)
    else:
        assert await validate_verdict(ctx, verdict) == verdict


async def test_output_feedback_is_bounded_and_never_retries_tool_dispatch():
    from pydantic_ai.exceptions import UnexpectedModelBehavior

    shell = FakeOpenShell()
    calls = 0

    def respond(messages, info):
        nonlocal calls
        calls += 1
        return final_response(info, evidence_ids=["invented"])

    with pytest.raises(UnexpectedModelBehavior, match="retries"):
        await build_agent(shell, FunctionModel(respond)).run(
            "Inspect",
            deps=await make_deps(shell),
        )
    assert calls == 3
    assert shell.executions == []


async def test_failed_offline_probe_and_successful_workspace_execution_require_inconclusive():
    shell = FakeOpenShell()
    native_execute = shell.execute

    async def execute(sandbox, command, **kwargs):
        result = await native_execute(sandbox, command, **kwargs)
        if sandbox.profile == "probe":
            return CommandResult(2, "", "python: can't open file '/tmp/probe.py'")
        return result

    shell.execute = execute
    calls = 0

    def respond(messages, info):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "run_probe",
                        {"command": "cd /tmp && python probe.py"},
                        tool_call_id="offline",
                    )
                ]
            )
        if calls == 2:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "execute", {"command": "python probe.py"}, tool_call_id="workspace"
                    )
                ]
            )
        if calls == 3:
            response = final_response(info, evidence_ids=["probe:1:offline", "execute:2:workspace"])
            response.parts[0].args["label"] = "potentially_exploitable"
            response.parts[0].args["citations"] = [dict(path="sink.py", start_line=1, end_line=1)]
            return response
        assert any(
            "is not a complete probe: exit code" in feedback
            for feedback in retry_feedback(messages)
        )
        return final_response(info, evidence_ids=["probe:1:offline", "execute:2:workspace"])

    result = await build_agent(shell, FunctionModel(respond)).run(
        "Inspect", deps=await make_deps(shell)
    )
    assert result.output.label == "inconclusive"
    assert len(shell.executions) == 2
    assert calls == 4
    assert shell.closed == ["probe-probe:1:offline"]


@pytest.mark.parametrize("final_line", [
    # Live cohort: Perl probes printed numeric claims and the agent spent its budget
    # on the generic "no parsed line" message.
    'HARNESS_PROBE {"target_reached":1,"oracle_valid":1,"positive_control":1,'
    '"negative_control":1,"vulnerability_observed":1}',
    "probe finished without a marker",
])
async def test_rejected_probe_line_gets_precise_feedback(final_line):

    from infosec_harness.agents.evidence import parse_probe_observations

    stdout = "context\n" * 2000 + final_line + "\n"  # longer than the tool-return excerpt
    assert parse_probe_observations(stdout) == {}
    rejected = final_line.startswith("HARNESS_PROBE ")
    shell = FakeOpenShell()
    native_execute = shell.execute

    async def execute(sandbox, command, **kwargs):
        await native_execute(sandbox, command, **kwargs)
        return CommandResult(0, stdout, "")

    shell.execute = execute
    calls = 0
    feedback = []

    def respond(messages, info):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ModelResponse(parts=[ToolCallPart(
                "run_probe", {"command": "perl probe.pl"}, tool_call_id="p")])
        if calls == 2:
            returned = tool_returns(messages, "run_probe")
            assert returned[0].observations["report_excerpted"] is True
            assert returned[0].observations.get("probe_line_rejected", False) is rejected
            response = final_response(info, evidence_ids=["probe:1:p"])
            response.parts[0].args.update(
                label="potentially_exploitable",
                citations=[dict(path="sink.pl", start_line=1, end_line=1)],
            )
            return response
        feedback.extend(retry_feedback(messages))
        return final_response(info)

    deps = await make_deps(shell)
    result = await build_agent(shell, FunctionModel(respond)).run("Probe", deps=deps)
    assert result.output.label == "inconclusive"
    message = feedback[-1]
    if rejected:
        assert "printed a final HARNESS_PROBE line that did not parse" in message
        assert "JSON boolean true or false" in message and "1/0" in message
        assert "vulnerability_observed" in message
        assert "has no parsed HARNESS_PROBE line" not in message
    else:
        assert "has no parsed HARNESS_PROBE line" in message
        assert "did not parse" not in message


async def test_split_probe_marker_feedback_repairs_with_new_bounded_probe():

    from infosec_harness.agents.evidence import parse_probe_observations

    observations = dict(
        target_reached=True,
        oracle_valid=True,
        positive_control=True,
        negative_control=True,
        vulnerability_observed=True,
    )
    split_marker = (
        json.dumps({**observations, "details": "observed controls"}) + "\nHARNESS_PROBE\n"
    )
    assert parse_probe_observations(split_marker) == {}
    shell = FakeOpenShell()
    native_execute = shell.execute

    async def execute(sandbox, command, **kwargs):
        await native_execute(sandbox, command, **kwargs)
        stdout = (
            split_marker
            if len(shell.executions) == 1
            else "HARNESS_PROBE " + json.dumps(observations) + "\n"
        )
        return CommandResult(0, stdout, "")

    shell.execute = execute
    calls = 0

    def respond(messages, info):
        nonlocal calls
        calls += 1
        if calls in (1, 3):
            if calls == 3:
                feedback = retry_feedback(messages)
                # The computed reason names the parse failure and the exact line contract.
                assert "has no parsed HARNESS_PROBE line" in feedback[-1]
                assert "share the final stdout line" in feedback[-1]
                assert "run a new corrected probe" in feedback[-1]
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "run_probe",
                        {"command": "python probe.py"},
                        tool_call_id="split" if calls == 1 else "repaired",
                    )
                ]
            )
        response = final_response(
            info, evidence_ids=["probe:1:split" if calls == 2 else "probe:3:repaired"]
        )
        response.parts[0].args.update(
            label="potentially_exploitable",
            citations=[dict(path="sink.py", start_line=1, end_line=1)],
        )
        return response

    result = await build_agent(shell, FunctionModel(respond)).run(
        "Inspect",
        deps=await make_deps(shell),
    )
    assert result.output.label == "potentially_exploitable"
    assert result.output.evidence_ids == ["probe:3:repaired"]
    assert len(shell.executions) == 2
    assert calls == 4
    assert shell.executions[0][2] != shell.executions[1][2]


async def test_blocked_target_feedback_requires_new_complete_probe():

    shell = FakeOpenShell()
    native_execute = shell.execute
    observations = dict(
        target_reached=False,
        oracle_valid=True,
        positive_control=True,
        negative_control=True,
        vulnerability_observed=False,
    )

    async def execute(sandbox, command, **kwargs):
        await native_execute(sandbox, command, **kwargs)
        # Mocked process evidence: normal read succeeds; the real callable rejects traversal.
        claims = {**observations, "target_reached": len(shell.executions) > 1}
        return CommandResult(
            0, "normal read OK; traversal BLOCKED\nHARNESS_PROBE " + json.dumps(claims), ""
        )

    shell.execute = execute
    calls = 0

    def respond(messages, info):
        nonlocal calls
        calls += 1
        if calls in (1, 3):
            if calls == 3:
                feedback = retry_feedback(messages)[-1]
                assert "target_reached=false" in feedback
                assert "even if its guard rejected it" in feedback
                assert "run a new corrected probe" in feedback
                assert "do not relabel" in feedback
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "run_probe",
                        {"command": "python probe.py"},
                        tool_call_id="blocked" if calls == 1 else "repaired",
                    )
                ]
            )
        response = final_response(
            info, evidence_ids=["probe:1:blocked" if calls == 2 else "probe:3:repaired"]
        )
        response.parts[0].args.update(
            label="likely_not_exploitable",
            citations=[dict(path="reader.py", start_line=1, end_line=1)],
        )
        return response

    result = await build_agent(shell, FunctionModel(respond)).run(
        "Inspect",
        deps=await make_deps(shell),
    )
    assert result.output.label == "likely_not_exploitable"
    assert result.output.evidence_ids == ["probe:3:repaired"]
    assert len(shell.executions) == 2
    assert calls == 4
    assert shell.executions[0][2] != shell.executions[1][2]


def test_model_and_tool_activities_share_one_ten_minute_single_attempt_config():
    """build_agent passes only activity_config; the library merges it into the model
    activity config, so model requests keep the 10-minute single-attempt schedule."""
    from datetime import timedelta

    from pydantic_ai.durable_exec.temporal import TemporalDurability

    agent = build_agent(FakeOpenShell(), FunctionModel(final_response))
    # Private attributes: the library exposes no public view of the merged configs.
    (durability,) = [
        capability
        for capability in agent._root_capability.capabilities
        if isinstance(capability, TemporalDurability)
    ]
    for config in (durability.activity_config, durability._model_activity_config):
        assert config["start_to_close_timeout"] == timedelta(minutes=10)
        assert config["retry_policy"].maximum_attempts == 1


async def test_oversized_write_is_refused_before_the_tool_runs():
    """The write tool has no size check of its own: the durable payload guard rejects
    arguments over MAX_INVOCATION_BYTES before the tool body (or any sandbox exec) runs."""
    from pydantic_ai.exceptions import UsageLimitExceeded

    from infosec_harness.sandbox.executor import MAX_INVOCATION_BYTES

    shell = FakeOpenShell()

    def respond(messages, info):
        content = "x" * MAX_INVOCATION_BYTES
        return ModelResponse(
            parts=[ToolCallPart("write", {"path": "big", "content": content}, tool_call_id="w")]
        )

    deps = await make_deps(shell)
    with pytest.raises(
        UsageLimitExceeded,
        match=rf"Tool call exceeds the durable payload budget \(\d+ > {MAX_INVOCATION_BYTES} bytes\)",
    ):
        await build_agent(shell, FunctionModel(respond)).run("Write", deps=deps)
    assert shell.executions == []
