"""Tests for the analysis engine: chunking, deduplication."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from stackwise.analyzer.engine import _run_llm_analysis
from stackwise.config import Engine, Settings
from stackwise.store.db import ScanDB


def test_llm_analysis_deduplicates_recommendations(scan_db: ScanDB, tmp_path: Path):
    """Duplicate recommendations from same category should be deduplicated."""
    settings = Settings(
        engine=Engine.OLLAMA,
        llm_chunk_size=50,
        llm_max_chunks=10,
        data_dir=tmp_path / "stackwise",
    )
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    # Add two resources
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-1", "us-east-1",
        metadata={"InstanceId": "i-1", "InstanceType": "t3.micro"},
    )
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-2", "us-east-1",
        metadata={"InstanceId": "i-2", "InstanceType": "t3.micro"},
    )

    client = MagicMock()
    # Simulate same recommendation returned twice (e.g. from two chunks)
    client.generate.return_value = (
        '[{"category": "cost", "title": "Enable S3 versioning", '
        '"detail": "x", "impact": "high", "effort": "low"}]'
    )
    dup_rec = {"category": "cost", "title": "Enable S3 versioning", "detail": "x",
               "impact": "high", "effort": "low"}
    client.parse_recommendations.side_effect = lambda x: [dup_rec, dup_rec]

    count = _run_llm_analysis(client, scan_db, scan.id, settings)
    recs = scan_db.get_recommendations(scan.id)
    # Should deduplicate to 1
    assert count == 1
    assert len(recs) == 1
    assert recs[0].title == "Enable S3 versioning"


def test_llm_analysis_chunks_large_categories(scan_db: ScanDB, tmp_path: Path):
    """Categories with > chunk_size resources should be processed in chunks."""
    settings = Settings(
        engine=Engine.OLLAMA,
        llm_chunk_size=5,
        llm_max_chunks=10,
        data_dir=tmp_path / "stackwise",
    )
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    for i in range(12):
        scan_db.insert_resource(
            scan.id, "ec2", "instance", f"i-{i}", "us-east-1",
            metadata={"InstanceId": f"i-{i}", "InstanceType": "t3.micro"},
        )

    client = MagicMock()
    client.generate.return_value = (
        '[{"category": "compute", "title": "Right-size", "detail": "y", '
        '"impact": "medium", "effort": "low"}]'
    )
    rightsize = {"category": "compute", "title": "Right-size", "detail": "y",
                 "impact": "medium", "effort": "low"}
    client.parse_recommendations.side_effect = lambda x: [rightsize]

    count = _run_llm_analysis(client, scan_db, scan.id, settings)
    # Should have been called 3 times (chunks of 5, 5, 2)
    assert client.generate.call_count == 3
    # Should have 3 recommendations (one per chunk, no dedupe since same title)
    recs = scan_db.get_recommendations(scan.id)
    assert len(recs) == 1  # Deduplicated - same title from all chunks
    assert count == 1


def test_llm_analysis_skips_discovery_category(scan_db: ScanDB, tmp_path: Path):
    """Tag/inventory noise should never reach the LLM — rules already cover it."""
    settings = Settings(
        engine=Engine.OLLAMA,
        llm_chunk_size=50,
        llm_max_chunks=10,
        data_dir=tmp_path / "stackwise",
    )
    scan = scan_db.create_scan("123", ["us-east-1"], ["discovery"])
    scan_db.insert_resource(
        scan.id, "resourcegroupstaggingapi", "resource", "r-1", "us-east-1",
        metadata={"ResourceARN": "arn:aws:ec2:...:instance/i-1"},
    )

    client = MagicMock()
    count = _run_llm_analysis(client, scan_db, scan.id, settings)

    client.generate.assert_not_called()
    assert count == 0


def test_llm_analysis_caps_resources_at_chunk_limit(scan_db: ScanDB, tmp_path: Path):
    """Resources beyond chunk_size * max_chunks are dropped, not sent unbounded."""
    settings = Settings(
        engine=Engine.OLLAMA,
        llm_chunk_size=2,
        llm_max_chunks=2,
        data_dir=tmp_path / "stackwise",
    )
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    for i in range(10):
        scan_db.insert_resource(
            scan.id, "ec2", "instance", f"i-{i}", "us-east-1",
            metadata={"InstanceId": f"i-{i}"},
        )

    client = MagicMock()
    client.generate.return_value = "[]"
    client.parse_recommendations.return_value = []

    _run_llm_analysis(client, scan_db, scan.id, settings)

    # chunk_size=2 * max_chunks=2 → at most 4 resources → 2 chunks
    assert client.generate.call_count == 2
