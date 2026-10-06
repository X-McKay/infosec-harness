"""PydanticAI model transport into a repository-free OpenShell sandbox."""

from typing import Literal

from pydantic_ai.messages import ModelResponse
from pydantic_ai.models import Model
from temporalio import activity

from .model_executor import MAX_INVOCATION_BYTES, MAX_RESPONSE_BYTES, RESPONSE, ModelInvocation
from .openshell import OpenShell


class ModelExecutorError(RuntimeError):
    """The executor ran to a terminal exit without a usable response; its receipt is complete."""


class OpenShellModel(Model):
    """Never creates a provider client or reads provider credentials on the worker."""

    def __init__(
        self,
        openshell: OpenShell,
        model_name: str,
        *,
        provider: Literal["openai", "bedrock"] = "openai",
        base_url: str | None = None,
        region: str = "us-east-1",
        timeout: int = 120,
    ) -> None:
        super().__init__()
        self.openshell = openshell
        self._model_name = model_name
        self.provider_name = provider
        self._base_url = base_url
        self.region = region
        self.timeout = timeout

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def system(self) -> str:
        return "openshell"

    async def request(self, messages, model_settings, model_request_parameters) -> ModelResponse:
        # Native PydanticAI durability owns this activity's stable identity and history.
        # Production inference without Temporal is deliberately unavailable.
        info = activity.info()
        budget = max(self.timeout - 10, 1)
        invocation = ModelInvocation(
            provider=self.provider_name,
            model_name=self.model_name,
            base_url=self._base_url,
            region=self.region,
            timeout_seconds=budget,
            messages=messages,
            settings=model_settings,
            parameters=model_request_parameters,
        )
        encoded = invocation.model_dump_json().encode()
        if len(encoded) > MAX_INVOCATION_BYTES:
            raise ValueError("Model invocation exceeds the durable payload budget")
        sandbox = await self.openshell.create(info.workflow_id, profile="model")
        result = await self.openshell.execute(
            sandbox,
            ["/usr/bin/timeout", "--preserve-status", "-s", "KILL", str(budget),
             "python", "-I", "-m", "infosec_harness.model_executor"],
            operation_id=f"model:{info.activity_id}",
            timeout=self.timeout,
            stdin=encoded,
        )
        if result.exit_code != 0 or result.output_truncated:
            # A complete native receipt with a failed executor: terminal, never resent.
            detail = result.stderr.rstrip().rsplit("\n", 1)[-1][-300:] if result.stderr else ""
            if result.exit_code == 137:
                detail = f"killed at the {budget}s executor budget; provider outcome unknown. {detail}"
            raise ModelExecutorError(
                f"OpenShell model executor returned no complete response "
                f"(exit {result.exit_code}, truncated={result.output_truncated}): {detail}"
            )
        if len(result.stdout.encode()) > MAX_RESPONSE_BYTES:
            raise ValueError("Model response exceeds the durable payload budget")
        return RESPONSE.validate_json(result.stdout)
