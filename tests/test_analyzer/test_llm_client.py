"""Tests for the Ollama LLM client."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from stackwise.analyzer.llm_client import LLMChunkError, OllamaClient, fit_resources
from stackwise.config import Settings


def test_parse_recommendations_valid_json():
    raw = (
        '[{"category": "cost", "title": "Right-size",'
        ' "detail": "x", "impact": "high", "effort": "low"}]'
    )
    recs = OllamaClient.parse_recommendations(raw)
    assert len(recs) == 1
    assert recs[0]["category"] == "cost"


def test_parse_recommendations_with_markdown_fences():
    raw = (
        '```json\n[{"category": "security",'
        ' "title": "Enable MFA", "detail": "y",'
        ' "impact": "high", "effort": "low"}]\n```'
    )
    recs = OllamaClient.parse_recommendations(raw)
    assert len(recs) == 1
    assert recs[0]["category"] == "security"


def test_parse_recommendations_json_embedded_in_text():
    raw = (
        'Here are my recommendations:\n'
        '[{"category": "reliability",'
        ' "title": "Add multi-AZ", "detail": "z",'
        ' "impact": "medium", "effort": "medium"}]'
        '\nHope this helps!'
    )
    recs = OllamaClient.parse_recommendations(raw)
    assert len(recs) == 1
    assert recs[0]["title"] == "Add multi-AZ"


def test_parse_recommendations_invalid_json():
    raw = "This is not JSON at all."
    recs = OllamaClient.parse_recommendations(raw)
    assert recs == []


def test_parse_recommendations_empty_response():
    recs = OllamaClient.parse_recommendations("")
    assert recs == []


def test_parse_recommendations_validates_schema():
    """Invalid/missing title or detail should be skipped; valid category normalized."""
    raw = (
        '[{"category": "invalid_cat", "title": "Valid", "detail": "d1"},'
        ' {"title": ""},'
        ' {"category": "security", "title": "No detail"},'
        ' {"category": "security", "title": "  Enable MFA  ", "detail": "d2"}]'
    )
    recs = OllamaClient.parse_recommendations(raw)
    assert len(recs) == 2  # Empty title and missing-detail items skipped
    assert recs[0]["category"] == "operational_excellence"  # invalid normalized
    assert recs[0]["title"] == "Valid"
    assert recs[1]["title"] == "Enable MFA"  # stripped


def test_parse_recommendations_skips_truncated_item_without_detail():
    """A title-only item (e.g. from a response cut off mid-array) is not actionable."""
    raw = '[{"category": "cost", "title": "Enable VPC flow logs"}]'
    recs = OllamaClient.parse_recommendations(raw)
    assert recs == []


def test_build_category_prompt():
    resources = [{"InstanceId": "i-123", "InstanceType": "t3.micro"}]
    findings = [{"title": "Public IP", "severity": "MEDIUM"}]
    prompt = OllamaClient.build_category_prompt("compute", resources, findings)

    assert "compute" in prompt
    assert "1 total" in prompt
    assert "i-123" in prompt
    assert "Public IP" in prompt


def test_build_category_prompt_with_chunk_context():
    """Chunk context appears when chunk_index and total_chunks provided."""
    resources = [{"id": "r1"}]
    findings = []
    prompt = OllamaClient.build_category_prompt(
        "data", resources, findings,
        chunk_index=1, total_chunks=3,
    )
    assert "chunk 2/3" in prompt


def _prompt_resources(prompt: str) -> list[dict]:
    return json.loads(prompt.split("### Resources\n", 1)[1].split("\n", 1)[0])


def test_build_category_prompt_drops_whole_resources_to_fit():
    """Resources JSON over 24KB loses whole resources, never a slice of JSON."""
    resources = [{"id": f"r-{i}", "padding": "x" * 200} for i in range(200)]
    prompt = OllamaClient.build_category_prompt("compute", resources, [])

    shown = _prompt_resources(prompt)
    assert 0 < len(shown) < len(resources)
    assert shown == resources[: len(shown)] == fit_resources(resources)
    assert len(json.dumps(shown)) <= 24_000
    assert f"{len(resources) - len(shown)} resources were omitted" in prompt
    assert "findings were omitted" not in prompt


def test_build_category_prompt_counts_omitted_findings_and_caller_drops():
    findings = [{"title": f"f{i}"} for i in range(35)]
    prompt = OllamaClient.build_category_prompt(
        "compute", [{"id": "r-1"}], findings, omitted_resources=4
    )
    assert "4 resources and 5 findings were omitted" in prompt
    assert len(json.loads(prompt.split("### Existing findings\n", 1)[1].split("\n", 1)[0])) == 30


def test_build_category_prompt_without_omissions_has_no_note():
    prompt = OllamaClient.build_category_prompt("compute", [{"id": "r-1"}], [])
    assert "omitted" not in prompt


def test_fit_resources_drops_a_resource_too_big_on_its_own():
    assert fit_resources([{"padding": "x" * 30_000}, {"id": "r-1"}]) == []


def test_parse_recommendations_dict_wrapped_recommendations_key():
    raw = (
        '{"recommendations": [{"category": "cost", "title": "T", '
        '"detail": "d", "impact": "low", "effort": "low"}]}'
    )
    recs = OllamaClient.parse_recommendations(raw)
    assert len(recs) == 1
    assert recs[0]["title"] == "T"


def test_parse_recommendations_dict_wrapped_items_key():
    raw = (
        '{"items": [{"category": "cost", "title": "T", '
        '"detail": "d", "impact": "low", "effort": "low"}]}'
    )
    recs = OllamaClient.parse_recommendations(raw)
    assert len(recs) == 1


def test_parse_recommendations_dict_with_non_list_value_returns_empty():
    raw = '{"recommendations": "not a list"}'
    assert OllamaClient.parse_recommendations(raw) == []


def test_parse_recommendations_dict_without_known_keys_returns_empty():
    raw = '{"foo": "bar"}'
    assert OllamaClient.parse_recommendations(raw) == []


def test_parse_recommendations_top_level_non_list_non_dict_returns_empty():
    raw = "42"
    assert OllamaClient.parse_recommendations(raw) == []


def test_parse_recommendations_extracted_array_still_invalid_json():
    """Text containing '[' and ']' but not valid JSON between them must fail
    cleanly, not raise."""
    raw = "prose before [ this is not json ] prose after"
    assert OllamaClient.parse_recommendations(raw) == []


def test_parse_recommendations_skips_non_dict_item():
    raw = '["just a string", {"category": "cost", "title": "T", "detail": "d"}]'
    recs = OllamaClient.parse_recommendations(raw)
    assert len(recs) == 1
    assert recs[0]["title"] == "T"


def test_client_init_sets_base_url_and_model():
    settings = Settings(ollama_url="http://localhost:11434/", model="qwen3:14b")
    client = OllamaClient(settings)
    assert client.base_url == "http://localhost:11434"
    assert client.model == "qwen3:14b"


def test_is_available_true_on_200():
    settings = Settings(ollama_url="http://localhost:11434")
    client = OllamaClient(settings)
    with patch("httpx.get", return_value=MagicMock(status_code=200)):
        assert client.is_available() is True


def test_is_available_false_on_non_200():
    settings = Settings(ollama_url="http://localhost:11434")
    client = OllamaClient(settings)
    with patch("httpx.get", return_value=MagicMock(status_code=500)):
        assert client.is_available() is False


def test_is_available_false_on_connection_error():
    settings = Settings(ollama_url="http://localhost:11434")
    client = OllamaClient(settings)
    with patch("httpx.get", side_effect=httpx.ConnectError("refused")):
        assert client.is_available() is False


def test_ensure_model_found_exact_match():
    settings = Settings(ollama_url="http://localhost:11434", model="qwen3:14b")
    client = OllamaClient(settings)
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"models": [{"name": "qwen3:14b"}]}
    with patch("httpx.get", return_value=resp):
        assert client.ensure_model() is True


def test_ensure_model_found_ignoring_latest_suffix():
    """A locally pulled 'qwen3:14b' tag should match a configured model name
    of just 'qwen3:14b' even if Ollama reports it differently tagged."""
    settings = Settings(ollama_url="http://localhost:11434", model="qwen3")
    client = OllamaClient(settings)
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"models": [{"name": "qwen3:14b"}]}
    with patch("httpx.get", return_value=resp):
        assert client.ensure_model() is True


def test_ensure_model_not_found():
    settings = Settings(ollama_url="http://localhost:11434", model="missing-model")
    client = OllamaClient(settings)
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"models": [{"name": "qwen3:14b"}]}
    with patch("httpx.get", return_value=resp):
        assert client.ensure_model() is False


def test_ensure_model_non_200_returns_false():
    settings = Settings(ollama_url="http://localhost:11434")
    client = OllamaClient(settings)
    with patch("httpx.get", return_value=MagicMock(status_code=503)):
        assert client.ensure_model() is False


def test_ensure_model_connection_error_returns_false():
    settings = Settings(ollama_url="http://localhost:11434")
    client = OllamaClient(settings)
    with patch("httpx.get", side_effect=httpx.ConnectError("refused")):
        assert client.ensure_model() is False


def test_generate_success_returns_response_text():
    settings = Settings(ollama_url="http://localhost:11434", model="qwen3:14b")
    client = OllamaClient(settings)
    resp = MagicMock()
    resp.json.return_value = {"response": "[]"}
    with patch("httpx.post", return_value=resp):
        assert client.generate("prompt") == "[]"


def test_generate_retries_then_succeeds():
    settings = Settings(ollama_url="http://localhost:11434", model="qwen3:14b")
    client = OllamaClient(settings)
    ok_resp = MagicMock()
    ok_resp.json.return_value = {"response": "[]"}

    with (
        patch(
            "httpx.post",
            side_effect=[httpx.ConnectError("refused"), ok_resp],
        ),
        patch("time.sleep"),
    ):
        assert client.generate("prompt", max_retries=3) == "[]"


def test_generate_all_retries_fail_raises():
    settings = Settings(ollama_url="http://localhost:11434", model="qwen3:14b")
    client = OllamaClient(settings)

    with (
        patch("httpx.post", side_effect=httpx.ConnectError("refused")) as post,
        patch("time.sleep"),
        pytest.raises(LLMChunkError, match="refused"),
    ):
        client.generate("prompt", max_retries=2)
    assert post.call_count == 2


def _resp(body=None, *, bad_json: bool = False) -> MagicMock:
    resp = MagicMock()
    if bad_json:
        resp.json.side_effect = json.JSONDecodeError("Expecting value", "<html>", 0)
    else:
        resp.json.return_value = body
    return resp


@pytest.mark.parametrize(
    "bad",
    [_resp(bad_json=True), _resp(["not", "a", "dict"]), _resp({"done": True}),
     _resp({"response": None})],
    ids=["invalid-json", "not-a-dict", "no-response-field", "response-not-text"],
)
def test_generate_retries_an_unusable_body_then_succeeds(bad: MagicMock):
    client = OllamaClient(Settings(ollama_url="http://localhost:11434"))
    with (
        patch("httpx.post", side_effect=[bad, _resp({"response": "[]"})]) as post,
        patch("time.sleep"),
    ):
        assert client.generate("prompt", max_retries=3) == "[]"
    assert post.call_count == 2


def test_generate_raises_when_every_body_is_unusable():
    client = OllamaClient(Settings(ollama_url="http://localhost:11434"))
    with (
        patch("httpx.post", return_value=_resp(bad_json=True)) as post,
        patch("time.sleep"),
        pytest.raises(LLMChunkError),
    ):
        client.generate("prompt", max_retries=3)
    assert post.call_count == 3


def test_generate_returns_empty_string_for_a_valid_empty_answer():
    client = OllamaClient(Settings(ollama_url="http://localhost:11434"))
    with patch("httpx.post", return_value=_resp({"response": ""})):
        assert client.generate("prompt") == ""
