"""OpenAI profile construction for the versioned atomic intake output schema."""

from __future__ import annotations

from typing import Any

from pydantic_ai.profiles import ModelProfile
from pydantic_ai.profiles.openai import OpenAIJsonSchemaTransformer


class InlineOpenAIJsonSchemaTransformer(OpenAIJsonSchemaTransformer):
    """Apply OpenAI strict-schema cleanup and inline local schema definitions.

    ``prefer_inlined_defs`` is a PydanticAI schema-transform implementation hook. Keep the
    dependency version/source pinned and the wire tests below when changing that dependency.
    """

    def __init__(self, schema: Any, *, strict: bool | None = None) -> None:
        super().__init__(schema, strict=strict)
        self.prefer_inlined_defs = True


def intake_openai_profile(base_profile: ModelProfile | None) -> ModelProfile:
    """Return a fresh intake profile mapping, overriding only its schema transformer.

    Pass this mapping as ``profile=`` when constructing the new-generation OpenAI model.
    Never mutate a cached model's profile after construction.
    """
    profile = dict(base_profile or {})
    profile["json_schema_transformer"] = InlineOpenAIJsonSchemaTransformer
    return profile
