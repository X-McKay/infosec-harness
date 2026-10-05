# Kubani inference disconnect investigation — 2026-10-05

Status: read-only investigation completed; disconnect cause unresolved. Live qualification remains blocked.

The user-requested Claude Opus diagnostic subprocess analyzed an explicitly approved,
redacted excerpt collected by the parent agent. Tools were disabled for that subprocess;
it did not access Kubernetes directly. The CLI reported `claude-opus-5-5`, successful
completion, and approximately $0.271 usage. Raw logs and its full report remain private.
No cluster settings, safety controls, or model requests were changed by this investigation.

## Confirmed observations

The serving path is Traefik → AI gateway → GPU broker → vLLM. Times below are UTC.

| Time | Observation |
| --- | --- |
| 17:04:34.535 | Gateway returned 200 after 2,078 ms; matching broker and vLLM 200s |
| 17:04:36.565 | Gateway returned 200 after 1,048 ms; matching broker and vLLM 200s |
| 17:04:40.814 | Third gateway request ended after 3,022 ms with no HTTP status or response usage recorded |
| 17:04:41.837 | vLLM logged another chat-completions 200, about one second after the gateway request ended |

The broker has health-check successes but no third chat-completions access line in
17:04:37–17:04:45. No matching exception appears in that saved window. The gateway's
complete third-request record has no error/reason field. Relevant serving pods did
not restart during the incident. The contemporaneous Traefik missing-certificate
error concerns a separate authentication ingress, not the model endpoint.

The active route is `llm-main-v1`. Its HTTPRoute has no explicit timeout. The configured
300-second timeout/retry policy targets `ai-v1`, so it does not establish this route's
effective timeout. Main backend HTTP/TCP override fields were empty. The other listed
policies target tracing on the gateway and health eviction on a different backend.

The model ingress annotations contain TLS/entrypoint settings and no middleware
attachment. Traefik's inspected deployment arguments have no responding/forwarding
timeout override and do not enable access logging. Historical access logs therefore
remain unavailable in the collected evidence; these arguments alone are not a complete
effective configuration dump.

The executor uses non-streaming `model.request`, with SDK retries disabled. Inspection
of the pinned OpenShell v0.1.2 proxy/relay code did not identify a matching three-second
deadline. Its response whole-body middleware bound is two minutes; this does not prove
that every possible timeout or connection-close path has been excluded.

Source: [pinned response relay](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-supervisor-network/src/l7/rest/http_response.rs).

## Interpretation and limits

Opus ranks a downstream close, potentially in the OpenShell egress path, above a
backend failure. The duration is suggestive of a deadline, not proof of one. Traefik,
gateway, broker and native relay cancellation/error paths remain possible.

The later vLLM 200 is plausibly the third request, but no shared request ID establishes
that correlation. Even if it is the same request, backend processing does not establish
client delivery. We therefore retain the unknown provider-outcome/cost classification;
Opus's conditional “generated, not delivered” interpretation is not promoted to fact.

The minimum next diagnostic experiment is a separate, bounded native request with
supervisor L7 logs retained through cleanup, correlated across all hops. An approved
fixture that delays HTTP response headers can isolate transport behavior without
replaying the failed model call. A fresh model cohort must wait for the cause/fix to
be established; the original attempt remains fenced and is not resent.

## Evidence integrity

Private evidence directory: `.harness/openshell/private/kubani-local-investigation/`.
Only this sanitized summary is committed. SHA-256 values:

| File | SHA-256 |
| --- | --- |
| `ai.log` | `940ef191fb68a769e0acab11bbb5dcbbf1b8fb1dfefd5eb3dd4b689df0209861` |
| `broker.log` | `3cf0cd030d49ed77a0ecca428165959b44e37369e921ea0d6e5252d2e3acf2ee` |
| `vllm.log` | `a1b83e56fbcd81ad96af2688a4df314dc8a7dd1c7029a5ab7ca3ea13f818f312` |
| `traefik.log` | `4f53ef6eece9537a0a23053a322dba617f1967b1cd35cbc003ac2172ad3cd2ef` |
| `opus-review-excerpt.txt` | `93e9b605efdaf69b8d8b37734382f33740dd0bf6a3b040cc9b5a9947d7819b03` |
| `opus-result.json` | `179161cd404eb27fb6e1f5e354867017a10705aed33ac1c90b14a562acc2c4f5` |
