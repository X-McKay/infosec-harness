# Live candidate 366e099 — failed, preserved

The native admission replay fix passed its focused tests and actual repeated
provider-attached model sandbox checks. A fresh ordinary 36-case cohort then ran
on clean commit `366e099fc965bb1198b1fe07a79d5cf841b44e20`, with unchanged limits,
ground truth, thresholds and the authorized self-hosted Qwen endpoint.

The first model response completed. The second native executor invocation exited
with a validation error before provider dispatch: the nested PydanticAI usage record
contained `output_reasoning_tokens`, which the wrapper rejected as an unexpected
keyword. Both command receipts are complete and untruncated. The new sandbox
admission observation succeeded, so this failure is distinct from the earlier
native replay defect.

PydanticAI deliberately preserves arbitrary provider-specific usage fields. Our
enclosing `ConfigDict(extra="forbid")` propagated into those SDK dataclasses and
conflicted with that native behavior. Removing the redundant enclosing rule permits
the native usage schema to preserve its extensions. This does not change provider
selection, endpoint validation, sandbox policy, request/response bounds or retry
behavior. A regression now serializes and validates an entire next-turn invocation
with reasoning usage extensions and checks that the response data is preserved.

The cohort is `failed` with zero completed cases and 35 unstarted. Task-success and
unsafe-negative gates are `not_checked`; no model-quality score is claimed. The
first successful response is retained, and no failed or unknown inference was resent.
Both native sandboxes were closed, the run fence persisted, explicit cleanup
reconciliation passed, and the owned worker stopped.

Private evidence directory:
`.harness/openshell/private/live-eval-v10-a9a835c7e5fa/`.

| Report | SHA-256 |
| --- | --- |
| `cohort-366e099.json` | `35c372d012fdf54f005f8e24d853a50072bf95f5d750dd4e392092e7079e022a` |
| `failure-summary.json` | `2cc7a2bcf187e81bd324712df9311fa3d3c657ba4bd3263bd4170f952987f6ab` |

The executor must be rebuilt from the corrected module and pass a native next-turn
decode check before another candidate cohort. Earlier successful typed calls do not
qualify multi-turn usage serialization.
