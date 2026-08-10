# GitHub Trending Follow-up

**Scan date:** 2026-08-09

## Method and Result

Reviewed GitHub's repository trending views for the preceding day, week, and month,
then inspected projects relevant to secure agent execution, code-context retrieval,
provider routing, durable context, skills, and hostile-document handling. Trending is a
discovery signal, not an adoption criterion: it does not establish security maturity,
maintenance capacity, license compatibility, data handling, or fitness for the
harness's trust boundary.

No project found in this pass should replace the harness's provider interface, policy
engine, evidence model, benchmark registry, or sandbox contract. The projects below
are feature inspiration and possible future comparison targets, not approved pilot
dependencies. Any adoption must pass the dependency and integration admission process.

## Candidates

| Project | Trending window observed | Relevance | Recommendation |
|---|---|---|---|
| [code-review-graph](https://github.com/tirth8205/code-review-graph) | Monthly | Local structural code graph and blast-radius context retrieval for code review | Reference only. A bounded offline comparison is permitted only after the built-in `EvidenceSlice` baseline proves an unmet retrieval gap. |
| [pdf-inspector](https://github.com/firecrawl/pdf-inspector) | Weekly | Local Rust/Python PDF classification and text extraction for advisories, reports, and tickets | Reference only. Do not add a document parser unless approved PDF evidence is a measured pilot requirement. |
| [code-graph-rag](https://github.com/vitali87/code-graph-rag) | Daily and weekly | Tree-sitter graph, structural search, and data-flow edges across languages | Use as design/reference material; do not add its Memgraph/Qdrant/MCP stack to the pilot. Reassess its graph extraction separately if the smaller spike is insufficient. |
| [OmniRoute](https://github.com/diegosouzapw/OmniRoute) | Monthly | Multi-provider routing, quotas, caching, cost, and fallback strategies | Do not integrate. Borrow only the ideas of versioned capability/price catalogs, cache-aware routing, and measured fallback value. |
| [TencentDB Agent Memory](https://github.com/TencentCloud/TencentDB-Agent-Memory) | Weekly and monthly | ACL-aware shared memory, skills, docs, and code graph | Do not integrate. Borrow explicit visibility and retrieval-budget ideas for a future curated-lesson store. |
| [Prime Agent](https://github.com/PrimeIntellect-ai/prime-agent) | Daily | Long-running, persistent, self-improving agent workflows | Do not integrate. It explicitly runs generated code with user permissions and states that it is not a security sandbox. Use it only as a reference for lifecycle/stop-state design. |
| [Agent Skills](https://github.com/addyosmani/agent-skills) and [Google Skills](https://github.com/google/skills) | Daily and weekly | Portable agent workflow packages with verification steps | Do not install third-party skills dynamically. Borrow the manifest, progressive-disclosure, and verification-gate pattern for internally reviewed capability packs. |

## Potential Future Comparisons

### 1. Code-context backend

`code-review-graph` uses Tree-sitter to create functions/classes/imports/call/test
relationships and computes a change blast radius, reducing the amount of source an
agent reads. It is MIT licensed and exposes an MCP-oriented integration, but its
installer writes platform configuration and injects instructions. That behavior is
incompatible with the harness's rule that repository and extension content is untrusted.

Do not add this project to the pilot. If a measured retrieval gap remains after the
owned `EvidenceSlice` builder is evaluated, run an offline, read-only comparison on a
frozen internal development corpus:

1. Build the graph in a disposable worker from a pinned source revision.
2. Extract a typed, deterministic context slice, without the project's MCP server,
   hooks, installer, or automatic configuration changes.
3. Compare retrieval coverage, source-token count, evidence-localization accuracy,
   triage precision/recall, latency, and operating cost against the existing
   search/tree tools.
4. Promote only if it improves a preregistered quality metric without hiding relevant
   counter-evidence or adding unacceptable graph-store retention.

The target interface is a local `CodeContextBackend`, not a shared database or a model
tool that can run arbitrary graph queries. This preserves repository and tenant
isolation.

### 2. Document-ingress preprocessor

`pdf-inspector` is MIT licensed, provides Python bindings, classifies text/scanned/mixed
PDFs, and extracts text locally. It is a potential preflight step for approved PDF
evidence such as vulnerability advisories or test reports. It is not general document
RAG and is not justified before a real pilot backlog requires PDFs.

Even a parser written in Rust must process hostile input. Execute it in the existing
document sandbox with size/page/time/memory limits, no network, no active content,
archive-expansion controls, and a separate OCR escalation approval. Retain the original
only under the artifact policy; never treat extracted text as instructions.

## Design Lessons Worth Adopting

### Context selection is a first-class cost and quality control

Both code-graph projects make a useful point: a code-review agent should retrieve a
small, structurally relevant slice rather than repeatedly read an entire monorepo. The
harness should add a measured code-context abstraction after basic search/tree retrieval
is working. It must expose coverage and omitted surfaces so token reduction is not
mistaken for review completeness.

### Persistent knowledge needs explicit ownership and promotion

TencentDB Agent Memory separates private, team, restricted, and agent-scoped memories,
then constrains retrieval by relevance and size. The equivalent harness feature should
be an immutable, human-reviewed `CuratedLesson` or policy/evidence artifact, not an
automatically accumulated model memory. It needs owner, scope, data classification,
evidence, expiry, and revocation fields. Raw transcripts and repository text remain
tainted and are not eligible for automatic promotion.

### Provider routing requires evidence, not advertised model counts

OmniRoute demonstrates useful routing dimensions: price, quota, latency, health,
context size, and prompt-cache affinity. The harness already needs a smaller version:
a dated capability/price catalog, provider-specific eligibility checks, sticky cache
prefixes, explicit fallback rules, and measurement of the quality gained per added
dollar. It must not silently send proprietary source to a new provider or replace a
chosen model with an unapproved fallback.

### Skills and extensions are a supply-chain surface

The skills projects encode workflows, verification gates, and progressive disclosure in
Markdown. That is useful structure, but skill/install content can change agent behavior
and may invoke tools. The harness should eventually support only signed, version-pinned,
internally reviewed capability packs with declared tools, data classes, sandbox profile,
tests, owner, expiry, and revocation. Third-party marketplace installation, `npx` at
runtime, and repository-provided skills remain prohibited. Scan candidate packages with
SkillSpector or equivalent before review, but retain human and runtime controls.

### Long-running autonomy is a future orchestration concern

Prime Agent's durable goals, stopping budgets, checkpoints, and resumable work are
useful reference features. Its own documentation warns that generated Python and project
commands run with user permissions and are not sandboxed. Keep the current explicit,
bounded state machine; adopt durability only after jobs require pause/resume and the
security model can preserve strict policy across restart.

## Explicit Non-Adoption Decisions

- Do not make an MCP server the primary interface for context retrieval or extensions.
  Prefer in-process typed tools; any future MCP integration runs inside the sandbox and
  is separately pinned and approved.
- Do not introduce a shared vector/graph/memory service in the pilot. It expands data
  retention, authorization, deletion, and cross-tenant risks before it solves a proven
  retrieval problem.
- Do not use a broad multi-provider gateway or automatically route to free/fallback
  providers. Provider/data approval is a hard prerequisite.
- Do not use self-improving or persistent agent frameworks as the production runtime.
  Improvement stays offline, reproducible, and gated by the held-out corpus.

## Follow-up Actions

1. Complete the owned `EvidenceSlice` baseline before proposing any retrieval product.
2. Require a measured workflow gap and dependency-admission record before any
   `CodeContextBackend` or `DocumentIngestor` experiment.
3. Keep workflow capabilities in owned, versioned code; introduce no skill or extension
   mechanism during the pilot.
4. Revisit the trending scan quarterly or when a pilot bottleneck is measured, rather
   than adopting tools because of popularity.
