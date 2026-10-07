# Framework choice: LangChain

## Track selected

This capstone uses the framework-based track with LangChain. The runtime entry points in the CLI, Streamlit app, and live demo use `LangChainCopilotAgent`, which builds a bounded LangChain [`create_agent`](https://docs.langchain.com/oss/python/langchain/agents) tool-calling agent. The current environment was verified with LangChain 1.4.3 and `langchain-openai` 1.6.7; `requirements.txt` allows compatible 1.x releases.

## What LangChain owns

- LLM-backed agent orchestration and tool selection through the configured Vocareum-compatible chat endpoint.
- Multi-step tool-call execution with a configured graph recursion limit, a per-request tool-call budget, and duplicate-call blocking.
- The chat model adapter through `langchain-openai`, configured only with `VOC_API_KEY`, `VOC_BASE_URL`, and `VOC_MODEL`.

The existing short-term conversation state and safe answer-style preferences are supplied as agent context and remain managed by the project's memory and feedback modules.

## What remains custom

Supply-chain logic remains in the project: requirements parsing, OSV lookups, dependency graph summaries, evidence-bound risk heuristics, CVSS v3.1 parsing, RAG document loading/retrieval, refusal policy, response guardrails, telemetry, and evaluation. LangChain does not receive shell, file-write, package-install, repository, or deployment tools. Deterministic refusal runs before agent invocation.

## Why this split

LangChain provides a recognizable framework agent and tool-routing layer while the security decisions remain inspectable Python code. The existing custom orchestrator remains available for regression tests and fallback when no Vocareum key is configured. Keeping the domain tools custom avoids coupling advisory validation and risk policy to framework internals.

## Tradeoffs and limits

The provider must support OpenAI-compatible chat tool calls; the project keeps the existing Vocareum base URL and credentials. No OpenAI provider migration is made. LangChain's planner is model-driven; `plan_question` adds deterministic intent hints but does not guarantee the model will follow them. Step and tool limits bound execution. This does not establish broad tool-selection accuracy. RAG uses an offline, curated concept-expanded sparse vector representation with cosine ranking, not a pretrained neural embedding model. The hand-authored relevance set is small. Independent analyst ratings, risk labels, and production deployment remain outstanding.
