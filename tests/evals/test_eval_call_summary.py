from pydantic_ai.messages import ModelResponse, ToolCallPart

from infosec_harness.evals.trajectory import summarize_calls


def test_call_summary_distinguishes_repeated_work_without_retaining_arguments():
    messages = [ModelResponse(parts=[
        ToolCallPart("read_file", {"path": "secret-path", "start": 1}),
        ToolCallPart("read_file", {"start": 1, "path": "secret-path"}),
        ToolCallPart("read_file", {"path": "different"}),
        ToolCallPart("final_result_positive", {"output": "sensitive"}),
    ])]
    summary = summarize_calls(messages, limit=2)
    assert summary["tool_call_count"] == 3
    assert summary["counts"] == {"read_file": 3}
    assert summary["repeated_call_count"] == 1
    assert summary["sequence_truncated"] is True
    assert len(summary["sequence"]) == 2
    assert summary["sequence"][0]["argument_id"] == summary["sequence"][1]["argument_id"]
    assert "sha256" not in str(summary)
    assert "secret-path" not in str(summary)
    assert "sensitive" not in str(summary)


def test_malformed_arguments_do_not_break_failure_diagnostics():
    summary = summarize_calls([ModelResponse(parts=[ToolCallPart("read_file", "{bad")])])
    assert summary["tool_call_count"] == 1
    assert summary["arguments_retained"] is False
