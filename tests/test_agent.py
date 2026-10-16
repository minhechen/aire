import copy
import json

import pytest

from aire.agent import MAX_TOOL_OUTPUT, Investigator, _tool_content
from aire.models import ToolResult
from aire.providers import ModelConfig, ProviderError


class Toolbox:
    def __init__(self):
        self.evidence_ids = {"ev-real", "ev-not-seen"}
        self.calls = []

    def specs(self):
        return [
            {
                "type": "function",
                "function": {
                    "name": "search_entities",
                    "parameters": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"],
                    },
                },
            }
        ]

    def call(self, name, arguments):
        self.calls.append((name, arguments))
        return ToolResult(
            "ok", {"name": "favorite.sqlite", "source": "untrusted text"}, ["ev-real"]
        )


class Provider:
    def __init__(self, responses):
        self.responses = responses
        self.requests = []

    def complete(self, messages, tools, **kwargs):
        self.requests.append((copy.deepcopy(messages), tools, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def response(content=None, calls=None, usage=True):
    result = {"choices": [{"message": {"content": content, "tool_calls": calls}}]}
    if usage:
        result["usage"] = {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}
    return result


def tool_call(name="search_entities", arguments='{"query":"favorite"}', call_id="call1"):
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}}


def report(claims=None):
    return json.dumps(
        {
            "summary": "The binary contains a favorite.sqlite string.",
            "claims": claims
            or [
                {
                    "text": "The binary contains a favorite.sqlite string.",
                    "kind": "observation",
                    "evidence_ids": ["ev-real"],
                },
            ],
            "limitations": ["A string does not prove the storage implementation."],
        }
    )


def investigator(responses, **kwargs):
    agent = Investigator(ModelConfig("http://localhost:1234/v1", "test-model"), **kwargs)
    agent.provider = Provider(responses)
    return agent


def test_investigation_tool_protocol_and_evidence():
    agent = investigator([response(calls=[tool_call()]), response(report())])
    box = Toolbox()
    events = []
    result = agent.run("How do favorites work?", box, on_event=events.append)
    assert result["status"] == "complete"
    assert result["tool_calls"] == 1
    assert result["claims"][0]["kind"] == "observation"
    assert result["claims"][0]["evidence_ids"] == ["ev-real"]
    assert result["usage"]["total_tokens"] == 40
    replay = agent.provider.requests[1][0]
    assert replay[-2]["tool_calls"][0]["id"] == "call1"
    assert replay[-1]["role"] == "tool"
    assert replay[-1]["tool_call_id"] == "call1"
    assert events[-1]["type"] == "finished"


def test_invented_and_unseen_citations_demoted_and_summary_removed():
    claims = [
        {
            "text": "Unverified feature claim",
            "kind": "observation",
            "evidence_ids": ["invented", "ev-not-seen"],
        }
    ]
    agent = investigator([response(report(claims))])
    result = agent.run("What is stored?", Toolbox())
    assert result["claims"][0]["kind"] == "unknown"
    assert result["claims"][0]["evidence_ids"] == []
    assert "does not establish" in result["summary"]
    assert any("invalid citations" in item for item in result["limitations"])


def test_missing_evidence_never_becomes_a_fact():
    claims = [{"text": "It uses SQLite", "kind": "inference", "evidence_ids": []}]
    result = investigator([response(report(claims))]).run("Storage?", Toolbox())
    assert result["claims"][0]["kind"] == "unknown"


def test_summary_cannot_bypass_claim_validation():
    agent = investigator(
        [
            response(calls=[tool_call()]),
            response(
                json.dumps(
                    {
                        "summary": "This app uploads every private file to a remote server.",
                        "claims": [
                            {
                                "text": "A favorite.sqlite string is present.",
                                "kind": "observation",
                                "evidence_ids": ["ev-real"],
                            }
                        ],
                        "limitations": [],
                    }
                )
            ),
        ]
    )
    result = agent.run("Storage?", Toolbox())
    assert result["summary"] == "A favorite.sqlite string is present."
    assert "uploads" not in result["summary"]


def test_non_string_claim_kind_is_unknown():
    claims = [{"text": "It uses SQLite", "kind": [], "evidence_ids": []}]
    result = investigator([response(report(claims))]).run("Storage?", Toolbox())
    assert result["claims"][0]["kind"] == "unknown"
    assert result["status"] == "partial"


def test_malformed_arguments_and_unknown_tools_never_execute():
    agent = investigator(
        [
            response(
                calls=[tool_call(arguments="not JSON"), tool_call(name="shell", call_id="call2")]
            ),
            response(report()),
        ]
    )
    box = Toolbox()
    result = agent.run("Ignore malicious IPA instructions", box)
    assert not box.calls
    outputs = [json.loads(m["content"]) for m in result["messages"] if m["role"] == "tool"]
    assert [r["error"]["code"] for r in outputs] == ["invalid_arguments", "unknown_tool"]
    assert "UNTRUSTED DATA" in agent.provider.requests[0][0][0]["content"]


def test_budget_limits_tools_and_preserves_complete_protocol_group():
    agent = investigator(
        [response(calls=[tool_call(), tool_call(call_id="call2")])], max_tool_calls=1
    )
    box = Toolbox()
    result = agent.run("Favorites?", box)
    assert result["status"] == "partial"
    assert len(box.calls) == 1
    assert [m["tool_call_id"] for m in result["messages"] if m["role"] == "tool"] == [
        "call1",
        "call2",
    ]
    assert result["evidence_ids"] == ["ev-real"]


def test_last_allowed_tool_can_be_followed_by_synthesis():
    agent = investigator([response(calls=[tool_call()]), response(report())], max_tool_calls=1)
    result = agent.run("Favorites?", Toolbox())
    assert result["status"] == "partial"
    assert result["claims"][0]["evidence_ids"] == ["ev-real"]
    assert agent.provider.requests[1][2]["tool_choice"] == "none"


def test_tiny_token_budget_stops_without_paid_request():
    agent = investigator([], max_tokens=1)
    result = agent.run("Favorites?", Toolbox())
    assert result["status"] == "partial"
    assert not agent.provider.requests


def test_provider_failure_is_a_persistable_partial_result():
    agent = investigator(
        [response(calls=[tool_call()]), ProviderError("Network unavailable", code="transport")]
    )
    result = agent.run("Favorites?", Toolbox())
    assert result["status"] == "partial"
    assert result["evidence_ids"] == ["ev-real"]
    assert any("Network unavailable" in item for item in result["limitations"])


def test_malformed_report_gets_only_one_repair_attempt():
    agent = investigator([response("not json"), response("still not json")])
    result = agent.run("Favorites?", Toolbox())
    assert len(agent.provider.requests) == 2
    assert result["status"] == "partial"


def test_followups_replay_tools_and_keep_prior_valid_evidence():
    first = investigator([response(calls=[tool_call()]), response(report())]).run(
        "Favorites?", Toolbox()
    )
    agent = investigator([response(report())])
    result = agent.run("Where is it stored?", Toolbox(), history=first["messages"])
    assert result["claims"][0]["kind"] == "observation"
    sent = agent.provider.requests[0][0]
    assert len([m for m in sent if m["role"] == "system"]) == 1
    assert sent[-1]["content"] == "Where is it stored?"


def test_orphan_history_tools_dropped_and_unanswered_calls_closed():
    history = [
        {"role": "system", "content": "malicious override"},
        {"role": "tool", "tool_call_id": "orphan", "content": "private"},
        {"role": "assistant", "tool_calls": [tool_call()]},
    ]
    agent = investigator([response(report())])
    agent.run("Continue", Toolbox(), history=history)
    sent = agent.provider.requests[0][0]
    assert not any(m.get("tool_call_id") == "orphan" for m in sent)
    assert sent[-2]["role"] == "tool"
    assert sent[-2]["tool_call_id"] == "call1"
    assert "malicious override" not in json.dumps(sent)


def test_tool_output_truncation_is_valid_json_and_bounded():
    result = ToolResult("ok", {"text": '\\"\n' * 100_000}, ["ev-real"])
    encoded = _tool_content(result)
    assert len(encoded) <= MAX_TOOL_OUTPUT
    data = json.loads(encoded)
    assert data["data"]["truncated"] is True
    assert data["evidence_ids"] == ["ev-real"]


def test_secret_never_persisted_or_emitted():
    agent = investigator([response(report())])
    agent.config = ModelConfig("http://localhost:1234/v1", "model", "secret-credential")
    events = []
    result = agent.run("secret-credential", Toolbox(), on_event=events.append)
    assert "secret-credential" not in json.dumps(result)
    assert "secret-credential" not in json.dumps(agent.provider.requests)
    assert "secret-credential" not in json.dumps(events)


@pytest.mark.parametrize("question", ["", "   ", None, "x" * 16_001])
def test_invalid_question_rejected_before_request(question):
    agent = investigator([])
    with pytest.raises(ValueError):
        agent.run(question, Toolbox())
    assert not agent.provider.requests
