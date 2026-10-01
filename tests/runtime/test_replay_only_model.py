"""Synthetic public wrapper/SDK activity checks; no service or provider calls."""

from __future__ import annotations

from typing import get_type_hints
from unittest.mock import AsyncMock

import pytest
from pydantic_ai import Agent
from pydantic_ai.durable_exec.temporal import TemporalDurability
from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.models.function import FunctionModel
from temporalio import activity
from temporalio.exceptions import ApplicationError
from temporalio.testing import ActivityEnvironment

from infosec_harness.agents.replay_only import ReplayOnlyModel, RetainedModelUnavailable


def guarded():
    base = FunctionModel(lambda messages, info: ModelResponse(parts=[TextPart("synthetic")]))
    for name in (
        "request",
        "count_tokens",
        "compact_messages",
        "cancel_suspended_response",
        "__aenter__",
    ):
        setattr(base, name, AsyncMock(side_effect=AssertionError("provider operation reached")))
    return base, ReplayOnlyModel(base)


def test_identity_profile_settings_and_preparation_preserved():
    base, model = guarded()
    assert model.model_id == base.model_id
    assert model.model_name == base.model_name
    assert model.system == base.system
    assert model.profile is base.profile
    assert model.settings is base.settings
    assert model.provider is base.provider
    params = ModelRequestParameters()
    assert model.prepare_request({"temperature": 0.0}, params) == base.prepare_request(
        {"temperature": 0.0}, params
    )
    assert model.prepare_messages([]) == base.prepare_messages([])
    assert model.customize_request_parameters(params) == base.customize_request_parameters(params)


@pytest.mark.asyncio
async def test_context_does_not_enter_underlying_provider():
    base, model = guarded()
    async with model as entered:
        assert entered is model
    base.__aenter__.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    ["request", "request_stream", "count_tokens", "compact_messages", "cancel_suspended_response"],
)
async def test_every_provider_operation_denied_without_delegation(operation):
    base, model = guarded()
    params = ModelRequestParameters()
    with pytest.raises(RetainedModelUnavailable, match="replay-only"):
        if operation == "request_stream":
            async with model.request_stream([], None, params):
                pytest.fail("stream must not start")
        elif operation == "compact_messages":
            await model.compact_messages(None)
        elif operation == "cancel_suspended_response":
            await model.cancel_suspended_response(ModelResponse(parts=[]))
        else:
            await getattr(model, operation)([], None, params)
    if operation != "request_stream":
        getattr(base, operation).assert_not_called()


@pytest.mark.asyncio
async def test_real_registered_sdk_model_activity_fails_nonretryably_before_provider():
    base, model = guarded()
    agent = Agent(model, name="intake", capabilities=[TemporalDurability()])
    durability = TemporalDurability.from_agent(agent)
    registered = next(
        fn
        for fn in durability.temporal_activities
        if activity._Definition.must_from_callable(fn).name == "agent__intake__model_request"
    )
    # Transport fixture type is obtained from the actual registered SDK activity signature;
    # production wrapper uses only public APIs, with no dependency on SDK private transport types.
    transport_type = get_type_hints(registered)["params"]
    params = transport_type(
        messages=[],
        model_settings=None,
        model_request_parameters=ModelRequestParameters(),
        serialized_run_context={"run_step": 2, "run_id": "synthetic-retry"},
    )
    with pytest.raises(ApplicationError) as caught:
        await ActivityEnvironment().run(registered, params, None)
    assert caught.value.type == "RetainedModelUnavailable"
    assert caught.value.non_retryable is True
    base.request.assert_not_called()
