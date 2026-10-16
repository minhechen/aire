"""Small, explicit OpenAI-compatible Chat Completions transport.

There is deliberately no default endpoint, model, or cloud credential discovery.
Only response metadata is surfaced on errors: provider bodies can contain secrets.
"""

from __future__ import annotations

import email.utils
import ipaddress
import json
import math
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


class ConfigurationError(ValueError):
    """The user must explicitly configure a valid model endpoint."""


class ProviderError(RuntimeError):
    """A sanitized transport or protocol error, safe to display or persist."""

    def __init__(self, message: str, *, code: str, status: int | None = None):
        super().__init__(message)
        self.code = code
        self.status = status


def _is_local(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class ModelConfig:
    base_url: str
    model: str
    api_key: str | None = field(default=None, repr=False)
    timeout: float = 45.0
    max_retries: int = 2
    allow_insecure_remote: bool = False
    max_response_bytes: int = 2_000_000

    def __post_init__(self) -> None:
        try:
            parsed = urllib.parse.urlsplit(self.base_url)
            host = parsed.hostname
            _ = parsed.port  # Validate port syntax without resolving any host.
        except (ValueError, TypeError):
            raise ConfigurationError("AIRE_BASE_URL must be a valid HTTP(S) URL.") from None
        if (
            parsed.scheme not in {"http", "https"}
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or any(ord(c) < 33 for c in self.base_url)
        ):
            raise ConfigurationError("AIRE_BASE_URL must be an HTTP(S) URL without credentials.")
        local = _is_local(host)
        if not local and parsed.scheme != "https" and not self.allow_insecure_remote:
            raise ConfigurationError("Remote model endpoints require HTTPS.")
        if not local and not self.api_key:
            raise ConfigurationError("AIRE_API_KEY is required for remote endpoints.")
        if not isinstance(self.model, str) or not self.model.strip():
            raise ConfigurationError("Set AIRE_MODEL explicitly; aire has no default model.")
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ConfigurationError("Provider timeout must be positive and finite.")
        if not isinstance(self.max_retries, int) or not 0 <= self.max_retries <= 5:
            raise ConfigurationError("Provider retries must be between 0 and 5.")
        if self.max_response_bytes < 1024:
            raise ConfigurationError("Provider response limit must be at least 1024 bytes.")
        if self.api_key and any(c in self.api_key for c in "\r\n"):
            raise ConfigurationError("The API key contains an invalid header character.")

    @classmethod
    def from_env(cls) -> ModelConfig:
        base_url = os.environ.get("AIRE_BASE_URL", "").strip()
        model = os.environ.get("AIRE_MODEL", "").strip()
        if not base_url or not model:
            raise ConfigurationError(
                "Set AIRE_BASE_URL and AIRE_MODEL, or use --offline. No default cloud is used."
            )
        return cls(
            base_url=base_url,
            model=model,
            api_key=os.environ.get("AIRE_API_KEY") or None,
            allow_insecure_remote=os.environ.get("AIRE_ALLOW_INSECURE_HTTP") == "1",
        )

    @property
    def endpoint(self) -> str:
        base = self.base_url.rstrip("/")
        return base if base.endswith("/chat/completions") else base + "/chat/completions"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, url: str):
        # In particular, never forward authorization or IPA data to a redirect host.
        raise urllib.error.HTTPError(req.full_url, code, "Redirect refused", headers, fp)


class ChatProvider:
    """Non-streaming transport with bounded retries, bodies, and wall time."""

    def __init__(self, config: ModelConfig):
        self.config = config
        handlers: list[Any] = [_NoRedirect()]
        if _is_local(urllib.parse.urlsplit(config.base_url).hostname or ""):
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int = 2048,
        deadline: float | None = None,
        tool_choice: str = "auto",
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "max_completion_tokens": max_tokens,
            "stream": False,
        }
        if tools:
            payload.update(tools=tools, tool_choice=tool_choice, parallel_tool_calls=False)
        body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(body) > 4_000_000:
            raise ProviderError("Model request exceeded its size limit.", code="request_too_large")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = "Bearer " + self.config.api_key
        request = urllib.request.Request(self.config.endpoint, data=body, headers=headers)
        for attempt in range(self.config.max_retries + 1):
            remaining = self._remaining(deadline)
            timeout = (
                min(self.config.timeout, remaining)
                if remaining is not None
                else self.config.timeout
            )
            retry_delay = min(0.5 * (2**attempt), 4.0)
            try:
                with self._opener.open(request, timeout=timeout) as response:
                    raw = self._read_response(response, deadline)
                if len(raw) > self.config.max_response_bytes:
                    raise ProviderError(
                        "Model response exceeded its size limit.", code="response_too_large"
                    )
                try:
                    result = json.loads(raw)
                except (ValueError, UnicodeError):
                    raise ProviderError(
                        "Model returned invalid JSON.", code="invalid_response"
                    ) from None
                if not isinstance(result, dict) or not isinstance(result.get("choices"), list):
                    raise ProviderError(
                        "Model returned an invalid completion.", code="invalid_response"
                    )
                return result
            except urllib.error.HTTPError as exc:
                status = exc.code
                if status not in {408, 409, 429} and not 500 <= status < 600:
                    exc.close()
                    raise ProviderError(
                        f"Model endpoint returned HTTP {status}.", code="http_error", status=status
                    ) from None
                retry_delay = self._retry_after(exc.headers.get("Retry-After"), retry_delay)
                exc.close()
                failure = ProviderError(
                    f"Model endpoint returned HTTP {status} after bounded retries.",
                    code="retry_exhausted",
                    status=status,
                )
            except (urllib.error.URLError, TimeoutError, OSError):
                failure = ProviderError(
                    "Model endpoint could not be reached within the transport budget.",
                    code="transport_error",
                )
            if attempt >= self.config.max_retries:
                raise failure from None
            remaining = self._remaining(deadline)
            if remaining is not None and retry_delay >= remaining:
                raise ProviderError("Model request exhausted the time budget.", code="deadline")
            time.sleep(retry_delay)
        raise AssertionError("unreachable")

    def _read_response(self, response: Any, deadline: float | None) -> bytes:
        chunks = []
        size = 0
        while size <= self.config.max_response_bytes:
            remaining = self._remaining(deadline)
            # urllib exposes no public per-read timeout setter. Updating the
            # underlying stdlib socket keeps a slow body inside the wall budget.
            sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
            if sock is not None and remaining is not None:
                sock.settimeout(min(self.config.timeout, remaining))
            chunk = response.read1(min(65536, self.config.max_response_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        self._remaining(deadline)
        return b"".join(chunks)

    @staticmethod
    def _remaining(deadline: float | None) -> float | None:
        if deadline is None:
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderError("Model request exhausted the time budget.", code="deadline")
        return remaining

    @staticmethod
    def _retry_after(value: str | None, fallback: float) -> float:
        if not value:
            return fallback
        try:
            delay = float(value)
        except ValueError:
            try:
                delay = email.utils.parsedate_to_datetime(value).timestamp() - time.time()
            except (ValueError, TypeError, OverflowError):
                return fallback
        return max(0.0, min(delay, 30.0)) if math.isfinite(delay) else fallback
