"""Local request ordinals from the agent run, independent of model factory caching."""
from contextvars import ContextVar

from pydantic_ai.capabilities import AbstractCapability

from infosec_harness.inference.wire.protocol import BrokerError

_IDENTITY: ContextVar[str | None] = ContextVar("broker_request_identity", default=None)


def current_request_identity() -> str:
    value = _IDENTITY.get()
    if value is None:
        raise BrokerError("identity", "Broker requests require a registered agent scheduling identity")
    return value


class BrokerRequestIdentity(AbstractCapability):
    async def wrap_model_request(self, ctx, *, request_context, handler):
        token = _IDENTITY.set(f"step:{ctx.run_step}")
        try:
            return await handler(request_context)
        finally:
            _IDENTITY.reset(token)
