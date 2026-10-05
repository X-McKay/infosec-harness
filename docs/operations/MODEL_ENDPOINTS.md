# Model endpoints

Stub inference is the default. Live inference uses either AWS Bedrock or an operator-configured
OpenAI-compatible chat-completions endpoint (the `gateway` backend in
`src/infosec_harness/config/models.yaml`). The packaged catalogue names no usable gateway
endpoint: an operator supplies one explicitly, and a live gateway run without one fails rather
than falling back to anything.

## Configure a gateway endpoint

```bash
export HARNESS_MODEL_MODE=live
export HARNESS_MODEL_BACKEND=gateway
export HARNESS_MODEL_BASE_URL=https://gateway.example.internal/v1
export HARNESS_OPENAI_API_KEY=...        # only if the gateway requires a key
```

`HARNESS_MODEL_BASE_URL` is required for every OpenAI-compatible backend: the packaged catalogue
ships no endpoint, and resolving a live model without one fails closed with
`ModelEndpointUnconfigured` rather than defaulting to a public API.

The catalogue maps each model tier (`opus`, `sonnet`, `haiku`) to a concrete model id per
backend. The `gateway:` column must name ids the endpoint actually serves
(`curl "$HARNESS_MODEL_BASE_URL/models"`). To change that mapping, prices or any other backend
setting, copy `src/infosec_harness/config/models.yaml` to an operator-owned file, edit it, and
point `HARNESS_MODELS_CONFIG` at the copy.

One backend serves every agent: `HARNESS_MODEL_BACKEND`, else the file's `default_backend`.
There is no per-agent routing. The file holds only `backends`, `default_backend`,
`model_catalog` and `model_policies`; any other key, including the retired
`agents.<name>.backend`, is rejected. A tier an agent or `harness eval run --model` names must
be in `model_catalog` with a model for the selected backend, or live resolution fails.

Settings worth knowing on an OpenAI-compatible backend:

| Setting | Effect |
| --- | --- |
| `prices` | Per-model input/output prices. A self-hosted model may declare zero; the cost basis is then reported as `zero_priced`, not as a real saving. |
| `min_max_tokens` | Raises every agent's `max_tokens` floor for reasoning models that spend thinking inside `max_tokens`. `0` disables it. |
| `enable_thinking` | Optional strict boolean sent as `chat_template_kwargs.enable_thinking` for Qwen-style templates. Omitted means provider default. |
| `thinking_token_budget` | Optional positive integer below the effective output ceiling, sent as the top-level body field `thinking_token_budget`; cannot be combined with `enable_thinking: false`. |
| `strict_closed_output_tools` | Marks closed output-tool schemas strict; a request, not proof that the server enforces a grammar. |
| `max_retries`, `max_retries_under_temporal` | Provider transport retries outside and inside Temporal. |

Setting or changing `enable_thinking`, `thinking_token_budget` or
`strict_closed_output_tools` changes model and contract provenance, so eval comparisons across
the change are not like-for-like. A brokered profile must declare the identical values
([broker runbook](../broker/RUNBOOK.md)). An accepted request field does not establish that the
server enforces it; vLLM, for example, needs a compatible version, reasoning parser and boundary
configuration for a thinking budget to take effect.

## Check an endpoint

`./dev validate --model`, or `harness ops model-connectivity --model` inside a configured process,
sends one structured-output request, as the verdict agent, to the selected backend with no
retry. A pass is connectivity, not agent quality. An endpoint whose `/v1/models` returns 200 can
still have a hung engine, so check an actual chat completion when diagnosing one. If an endpoint fails during an
evaluation, stop the cohort, keep its scored, interrupted and unstarted attempts, and start any
resumed run as a new cohort: never stitch partial scores from two runs together.

## Bedrock

Locally, `aws sso login --profile infosec-harness-sso` and `HARNESS_MODEL_BACKEND=bedrock`; the
worker reads `~/.aws` read-only. In Kubernetes leave `AWS_PROFILE` unset and use workload
identity. Confirm the Bedrock model ids and region in the catalogue match what the account has
enabled, adding a `us.` or `global.` inference-profile prefix where required.
