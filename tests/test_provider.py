import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aire.providers import ChatProvider, ConfigurationError, ModelConfig, ProviderError


@pytest.fixture
def endpoint():
    replies = []
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append((self.path, dict(self.headers), json.loads(body)))
            status, headers, response = replies.pop(0)
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(
                response if isinstance(response, bytes) else json.dumps(response).encode()
            )

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/v1", replies, requests
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def completion():
    return {"choices": [{"message": {"role": "assistant", "content": "hello"}}]}


def test_no_default_model_or_cloud(monkeypatch):
    for name in ("AIRE_BASE_URL", "AIRE_MODEL", "AIRE_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "not-discovered")
    with pytest.raises(ConfigurationError, match="No default cloud"):
        ModelConfig.from_env()


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "[::1]"])
def test_local_key_optional(host):
    assert ModelConfig(f"http://{host}:1234/v1", "chosen-model").api_key is None


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/v1",
        "https://user:password@example.com/v1",
        "https://example.com/v1?secret=x",
        "https://example.com/v1#fragment",
        "http://example.com/v1",
        "https://example.com:bad/v1",
        "http://localhost.evil/v1",
    ],
)
def test_invalid_or_insecure_url_is_rejected(url):
    with pytest.raises(ConfigurationError):
        ModelConfig(url, "chosen-model", api_key="test-secret")


def test_remote_key_required_and_secret_not_in_repr():
    with pytest.raises(ConfigurationError, match="AIRE_API_KEY"):
        ModelConfig("https://example.com/v1", "chosen-model")
    config = ModelConfig("https://example.com/v1", "chosen-model", api_key="test-secret")
    assert "test-secret" not in repr(config)
    assert ModelConfig("http://example.com/v1", "model", "key", allow_insecure_remote=True)


def test_explicit_environment_config(monkeypatch):
    monkeypatch.setenv("AIRE_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.setenv("AIRE_MODEL", "local-model")
    monkeypatch.delenv("AIRE_API_KEY", raising=False)
    config = ModelConfig.from_env()
    assert config.model == "local-model"
    assert config.endpoint == "http://localhost:1234/v1/chat/completions"


def test_chat_payload_and_authorization(endpoint):
    base, replies, requests = endpoint
    replies.append((200, {}, completion()))
    tools = [{"type": "function", "function": {"name": "search", "parameters": {}}}]
    provider = ChatProvider(ModelConfig(base, "explicit-model", "local-test-key"))
    result = provider.complete([{"role": "user", "content": "收藏"}], tools, max_tokens=100)
    path, headers, payload = requests[0]
    assert path == "/v1/chat/completions"
    assert headers["Authorization"] == "Bearer local-test-key"
    assert payload["model"] == "explicit-model"
    assert payload["max_completion_tokens"] == 100
    assert payload["tools"] == tools
    assert payload["parallel_tool_calls"] is False
    assert result == completion()


def test_transient_retry_after_and_no_error_body_leak(endpoint):
    base, replies, requests = endpoint
    replies.extend([(429, {"Retry-After": "0"}, b"secret-provider-body"), (200, {}, completion())])
    result = ChatProvider(ModelConfig(base, "model")).complete([], [])
    assert result == completion()
    assert len(requests) == 2


def test_permanent_error_is_sanitized_and_not_retried(endpoint):
    base, replies, requests = endpoint
    replies.append((401, {}, b"api-key-and-private-app-data"))
    with pytest.raises(ProviderError) as caught:
        ChatProvider(ModelConfig(base, "model")).complete([], [])
    assert caught.value.status == 401
    assert "private" not in str(caught.value)
    assert len(requests) == 1


def test_retry_exhaustion_is_bounded(endpoint):
    base, replies, requests = endpoint
    replies.extend([(503, {"Retry-After": "0"}, b"private")] * 3)
    with pytest.raises(ProviderError, match="bounded retries"):
        ChatProvider(ModelConfig(base, "model", max_retries=2)).complete([], [])
    assert len(requests) == 3


def test_redirect_is_not_followed(endpoint):
    base, replies, requests = endpoint
    replies.append((307, {"Location": "http://example.com/stolen"}, b""))
    with pytest.raises(ProviderError) as caught:
        ChatProvider(ModelConfig(base, "model", "sensitive")).complete([], [])
    assert caught.value.status == 307
    assert len(requests) == 1


@pytest.mark.parametrize(
    "body,code",
    [
        (b"not json", "invalid_response"),
        (b"[]", "invalid_response"),
        (b"x" * 2000, "response_too_large"),
    ],
)
def test_response_validation_and_size_bound(endpoint, body, code):
    base, replies, _ = endpoint
    replies.append((200, {}, body))
    with pytest.raises(ProviderError) as caught:
        ChatProvider(ModelConfig(base, "model", max_response_bytes=1024)).complete([], [])
    assert caught.value.code == code


def test_expired_deadline_makes_no_request(endpoint):
    base, _, requests = endpoint
    with pytest.raises(ProviderError) as caught:
        ChatProvider(ModelConfig(base, "model")).complete([], [], deadline=time.monotonic() - 1)
    assert caught.value.code == "deadline"
    assert not requests


def test_retry_after_cannot_exceed_deadline(endpoint):
    base, replies, requests = endpoint
    replies.append((429, {"Retry-After": "30"}, b""))
    with pytest.raises(ProviderError) as caught:
        ChatProvider(ModelConfig(base, "model")).complete([], [], deadline=time.monotonic() + 1)
    assert caught.value.code == "deadline"
    assert len(requests) == 1
