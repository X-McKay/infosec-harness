"""Static replay/profile facade; it has no channel or provider execution capability."""
from pydantic_ai.models import Model

from infosec_harness.inference.compat import contract_profile
from infosec_harness.inference.protocol import BrokerError


class UnboundBrokerModel(Model):
    def __init__(self, model_name: str, *, atomic_intake: bool):
        super().__init__(profile=contract_profile(model_name, atomic_intake=atomic_intake))
        self._model_name = model_name

    @property
    def model_name(self):
        return self._model_name

    @property
    def system(self):
        return "openai"

    async def request(self, *args, **kwargs):
        raise BrokerError("identity", "Unbound replay models cannot dispatch inference")
