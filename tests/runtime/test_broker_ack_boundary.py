"""Controlled response-boundary tests: fake native provider, real broker transport/controller."""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import httpx
import pytest
from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart, UserPromptPart
from pydantic_ai.models import ModelRequestParameters
from test_openshell_controller import controller_fixture

from infosec_harness.inference.codec import encode_response
from infosec_harness.inference.protocol import (
    BrokerError,
    InferenceRequest,
    InferenceResult,
    TransientBrokerError,
    canonical_bytes,
)
from infosec_harness.inference.transport import BrokerModel


def setup_boundary(tmp_path, monkeypatch, *, saved, detached=False):
    core, template, lease, events, rows = controller_fixture(tmp_path)
    core.clock = time.time
    binding = template.binding.model_copy(update={'expires_at': time.time() + 600})
    started, release = asyncio.Event(), asyncio.Event()
    dispatched = []
    bodies = []
    server_tasks = []
    async def native_post(_url, body, _headers, **_options):
        request = InferenceRequest.model_validate_json(body)
        permit = await core.ledger.claim(request.request_id, lease_id=lease.lease_id)
        dispatched.append(request.request_id)
        started.set()
        await release.wait()
        if saved:
            result = InferenceResult(request_id=request.request_id,
                response=encode_response(ModelResponse(parts=[TextPart('saved response')], model_name=template.contract.model)))
            await core.ledger.complete(result, permit=permit)
        # Simulate native ACK loss after the ledger decision, never an upstream retry.
        raise BrokerError('unavailable')
    core.channel = SimpleNamespace(post=native_post)
    async def handler(request):
        bodies.append(request.content)
        try:
            if detached:
                task = asyncio.create_task(core.handle(request.url.path, request.content, dict(request.headers)))
                server_tasks.append(task)
                result = await asyncio.shield(task)
            else:
                result = await core.handle(request.url.path, request.content, dict(request.headers))
            return httpx.Response(200, content=canonical_bytes(result))
        except BrokerError as error:
            return httpx.Response(409, content=canonical_bytes({'error': error.code}))
    monkeypatch.setenv('BROKER_FAKE_ACK_KEY', 'a' * 32)
    model = BrokerModel(contract=template.contract, binding=binding, controller_url='https://controller.test',
        secret_env='BROKER_FAKE_ACK_KEY', ca_file=None, client_cert=None, client_key=None,
        request_identity=lambda: 'stable-model-activity', http_transport=httpx.MockTransport(handler))
    model._qualification_server_tasks = server_tasks
    return core, model, started, release, dispatched, bodies, events, rows


async def test_delayed_ack_exact_pending_retry_preserves_winner_and_saved_response(tmp_path, monkeypatch):
    _core, model, started, release, dispatched, bodies, events, rows = setup_boundary(tmp_path, monkeypatch, saved=True)
    messages = [ModelRequest(parts=[UserPromptPart('controlled synthetic response-boundary fixture')])]
    params = ModelRequestParameters()
    leader = asyncio.create_task(model.request(messages, model.contract.model_settings, params))
    await asyncio.wait_for(started.wait(), 5)
    with pytest.raises(TransientBrokerError, match='pending'):
        await model.request(messages, model.contract.model_settings, params)
    assert len(dispatched) == 1 and 'revoke' not in events and 'recover' not in events
    release.set()
    response = await asyncio.wait_for(leader, 5)
    again = await model.request(messages, model.contract.model_settings, params)
    assert response == again and response.parts[0].content == 'saved response'
    assert len(dispatched) == 1 and len(bodies) == 3 and all(body == bodies[0] for body in bodies)
    assert list(rows.values())[0].state == 'completed'
    assert 'revoke' not in events and 'recover' not in events


async def test_true_uncommitted_ack_loss_remains_unknown_and_never_redispatches(tmp_path, monkeypatch):
    _core, model, started, release, dispatched, bodies, events, rows = setup_boundary(tmp_path, monkeypatch, saved=False)
    messages = [ModelRequest(parts=[UserPromptPart('controlled synthetic unknown-boundary fixture')])]
    params = ModelRequestParameters()
    leader = asyncio.create_task(model.request(messages, model.contract.model_settings, params))
    await asyncio.wait_for(started.wait(), 5)
    release.set()
    with pytest.raises(BrokerError, match='completion_unknown'):
        await asyncio.wait_for(leader, 5)
    with pytest.raises(BrokerError, match='completion_unknown') as repeated:
        await model.request(messages, model.contract.model_settings, params)
    assert type(repeated.value) is BrokerError
    assert len(dispatched) == 1 and bodies[0] == bodies[1]
    assert list(rows.values())[0].state == 'completion_unknown'
    assert events.count('revoke') == events.count('recover') == 1


async def test_worker_timeout_before_ack_does_not_cancel_server_winner_or_redispatch(tmp_path, monkeypatch):
    _core, model, started, release, dispatched, bodies, events, rows = setup_boundary(
        tmp_path, monkeypatch, saved=True, detached=True)
    model.timeout = 0.02  # Controlled client deadline; production timing constants are unchanged.
    messages = [ModelRequest(parts=[UserPromptPart('controlled synthetic client timeout fixture')])]
    params = ModelRequestParameters()
    with pytest.raises(TransientBrokerError, match='unavailable'):
        await model.request(messages, model.contract.model_settings, params)
    assert started.is_set() and len(dispatched) == 1
    with pytest.raises(TransientBrokerError, match='pending'):
        await model.request(messages, model.contract.model_settings, params)
    assert 'revoke' not in events and 'recover' not in events
    release.set()
    await asyncio.wait_for(model._qualification_server_tasks[0], 5)
    result = await model.request(messages, model.contract.model_settings, params)
    assert result.parts[0].content == 'saved response'
    assert len(dispatched) == 1 and len(bodies) == 3 and all(body == bodies[0] for body in bodies)
    assert list(rows.values())[0].state == 'completed'
    assert 'revoke' not in events and 'recover' not in events
