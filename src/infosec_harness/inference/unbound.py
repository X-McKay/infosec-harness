"""Static replay/profile facade; it has no channel or provider execution capability."""
from pydantic_ai.models import Model
from pydantic_ai.providers.openai import OpenAIProvider

from infosec_harness.inference.protocol import BrokerError


class UnboundBrokerModel(Model):
    def __init__(self, model_name: str, *, atomic_intake: bool):
        profile = OpenAIProvider.model_profile(model_name) or {}
        if atomic_intake:
            from infosec_harness.agents.intake_schema import intake_openai_profile
            profile = intake_openai_profile(profile)
        super().__init__(profile=profile)
        self._model_name = model_name

    @property
    def model_name(self):
        return self._model_name

    @property
    def system(self):
        return "openai"

    async def request(self, *args, **kwargs):
        raise BrokerError("identity", "Unbound replay models cannot dispatch inference")
