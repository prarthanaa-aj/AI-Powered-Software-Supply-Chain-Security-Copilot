"""Vocareum-compatible chat client kept behind a provider boundary."""
import logging
from time import perf_counter
from openai import OpenAI
from app.config import VOC_API_KEY, VOC_BASE_URL, VOC_MODEL

logger = logging.getLogger(__name__)


class LLMClient:
    def __init__(self, api_key: str | None = None, base_url: str | None = None, model: str | None = None):
        self.api_key = api_key if api_key is not None else VOC_API_KEY
        self.base_url = base_url or VOC_BASE_URL
        self.model = model or VOC_MODEL
        self._client = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=30.0, max_retries=2) if self.api_key else None
        self.last_request_metrics = {}

    @property
    def available(self) -> bool:
        return self._client is not None

    def complete(self, messages: list[dict], tools: list[dict] | None = None, max_tokens: int = 900):
        if not self._client:
            raise RuntimeError("VOC_API_KEY is not configured")
        started = perf_counter()
        kwargs = {"model": self.model, "messages": messages, "max_tokens": max_tokens}
        if tools:
            kwargs.update(tools=tools, tool_choice="auto")
        response = self._client.chat.completions.create(**kwargs)
        elapsed = perf_counter() - started
        usage = getattr(response, "usage", None)
        self.last_request_metrics = {
            "latency_seconds": round(elapsed, 4),
            "prompt_tokens": getattr(usage, "prompt_tokens", 0) or 0,
            "completion_tokens": getattr(usage, "completion_tokens", 0) or 0,
        }
        logger.info("llm_request_complete model=%s latency_seconds=%.3f prompt_tokens=%s completion_tokens=%s", self.model, elapsed, getattr(usage, "prompt_tokens", None), getattr(usage, "completion_tokens", None))
        return response
