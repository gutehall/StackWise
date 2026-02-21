"""Tests for the Ollama LLM client."""

from __future__ import annotations

from stackwise.analyzer.llm_client import OllamaClient


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
    """Invalid or missing title should be skipped; valid category normalized."""
    raw = (
        '[{"category": "invalid_cat", "title": "Valid"},'
        ' {"title": ""},'
        ' {"category": "security", "title": "  Enable MFA  "}]'
    )
    recs = OllamaClient.parse_recommendations(raw)
    assert len(recs) == 2  # Empty title skipped
    assert recs[0]["category"] == "operational_excellence"  # invalid normalized
    assert recs[0]["title"] == "Valid"
    assert recs[1]["title"] == "Enable MFA"  # stripped


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
