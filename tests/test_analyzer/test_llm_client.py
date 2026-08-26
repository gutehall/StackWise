"""Tests for the Ollama LLM client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from stackwise.analyzer.llm_client import OllamaClient
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


def test_build_category_prompt_truncates_large_resource_payload():
    """Resources JSON over 24KB must be truncated to stay within context."""
    resources = [{"id": f"r-{i}", "padding": "x" * 200} for i in range(200)]
    prompt = OllamaClient.build_category_prompt("compute", resources, [])
    assert "... (truncated)" in prompt


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


def test_generate_all_retries_fail_returns_empty_string():
    settings = Settings(ollama_url="http://localhost:11434", model="qwen3:14b")
    client = OllamaClient(settings)

    with (
        patch("httpx.post", side_effect=httpx.ConnectError("refused")),
        patch("time.sleep"),
    ):
        assert client.generate("prompt", max_retries=2) == ""
