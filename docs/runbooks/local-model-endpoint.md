# Recover the local inference endpoint

The repository owner authorizes this recovery procedure for `https://llm.almckay.io/v1`. Use it when the inference engine is unavailable or hung. Use the configured Kubernetes context and an existing `kubectl` installation.

Stop the affected evaluation cohort and preserve its scored, interrupted, and unstarted attempts before restarting the endpoint. Endpoint recovery is operational evidence; it does not qualify an agent or convert an incomplete cohort into a completed one.

Delete the vLLM pod by label:

```bash
kubectl -n vllm delete pod -l app=vllm
```

Kubernetes creates a replacement. Do not use `kubectl rollout restart`: Flux removes the rollout marker during its next sync, causing a second restart.

Watch the replacement:

```bash
kubectl -n vllm get pods -l app=vllm -w
```

Model loading takes approximately six minutes. Wait for the replacement to show `1/1 Running`, then end the watch and check actual chat generation:

```bash
curl -sS -m 60 https://llm.almckay.io/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"Qwen3.6-35B-A3B-NVFP4","messages":[{"role":"user","content":"What is 12*12?"}],"max_tokens":10,"chat_template_kwargs":{"enable_thinking":false}}'
```

Check that the response contains generated text from the expected model, rather than an HTTP or engine error. The ten-token limit may truncate the answer; actual text generation establishes serving, but a truncated response does not establish complete arithmetic correctness. `/v1/models` returning 200 is insufficient: it can succeed while the engine is hung.

Record the deleted and replacement pod, readiness state, chat status, generation/truncation status, and recovery timestamps separately from qualification. Any resumed evaluation is a declared fresh cohort with its own artifacts and attempt cap; preserve the failed cohort and never stitch its partial scores into the new one.

## Optional reasoning-token budget

An OpenAI-compatible backend can declare `thinking_token_budget` as a strict positive integer,
for example `4000` with an effective output ceiling of `16000`. The budget must be below that
ceiling and cannot be combined with `enable_thinking: false`. The authenticated broker profile
must declare the identical value. Agent settings cannot supply arbitrary request-body overrides.
The shared direct, executor, and admission renderer sends the setting as the top-level provider
body field `thinking_token_budget`; it is separate from `chat_template_kwargs.enable_thinking`.

Current [vLLM reasoning documentation](https://docs.vllm.ai/en/stable/features/reasoning_outputs/#thinking-budget-control)
describes counting reasoning tokens from a configured start boundary and forcing the end
boundary when the budget is reached. This requires a compatible serving version, reasoning
parser, and boundary configuration. A model name or accepted HTTP field does not establish that
the deployed server enforces the budget. A separate direct probe against the observed vLLM 0.30 serving process with its Qwen3 parser
used a 32-token reasoning cap and a 512-token total ceiling. It returned 31 reasoning tokens
and a correct arithmetic `final_result` tool call. This establishes an observed transition for
that probe; a 4,000-token agent candidate, brokered enforcement, and complete structured/tool
behavior remain `not_checked`.
A separate one-request continuation of a retained reasoning-only build response used a
4,000-token reasoning cap and a 16,000-token total ceiling. It returned 573 reasoning tokens
and one schema-valid `final_result`, without retries or executing tools. That response did
not reach the cap, so it does not establish that the cap caused the changed outcome or that
the complete agent succeeds. Both direct probes remain separate from broker qualification.

Leaving the option unset preserves historical serialized contracts and configuration digests.
Setting or changing it changes model/profile/contract provenance and requires fresh authorization
and readiness evidence. It does not raise total output, request, input, cost, retry, or case-time
limits, and does not retry unknown completions. Old durable payloads omit the optional field and
retain their prior behavior. The executor's packaged compatibility code changes, so a newly
qualified executor image is needed before a live brokered candidate uses the option.

A reasoning cap does not repair missing environment installation commands. The retained
env-planner failure exhausted semantic warmup retries after omitting `install_commands`;
that output-validation issue is separate. Complete answers, semantic gates, hosted deployment,
and 4,000-token brokered enforcement remain `not_checked` until their respective checks actually run.

Use existing backend routing to opt individual agents into a separately named backend with
`thinking_token_budget: 4000`, and give its authenticated executor profile the same value. For
example, an operator model file can route `agents.build-repair.backend` to that backend. Copy
the reviewed endpoint, model catalog, price ceilings, transport, and all other backend settings;
the packaged default remains unchanged. This routing example is configuration guidance, not
a qualified production configuration.
