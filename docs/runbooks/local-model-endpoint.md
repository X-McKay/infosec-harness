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
