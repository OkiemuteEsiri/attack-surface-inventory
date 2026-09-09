import json
from pathlib import Path

import pytest

from src.inventory import load_inventory, normalize_record, stale_assets


def base_record():
    return {
        "asset_id": "A-1",
        "hostname": "HOST-01.EXAMPLE",
        "asset_type": "Server",
        "owner": "Platform",
        "business_service": "Portal",
        "criticality": 4,
        "internet_exposed": False,
        "environment": "Production",
        "operating_system": "Linux",
        "last_seen_days": 2,
    }


def test_normalization_lowercases_selected_fields():
    asset = normalize_record(base_record())
    assert asset.hostname == "host-01.example"
    assert asset.asset_type == "server"
    assert asset.environment == "production"


def test_invalid_criticality_rejected():
    record = base_record()
    record["criticality"] = 9
    with pytest.raises(ValueError):
        normalize_record(record)


def test_missing_required_field_rejected():
    record = base_record()
    del record["owner"]
    with pytest.raises(ValueError):
        normalize_record(record)


def test_duplicate_asset_ids_rejected(tmp_path: Path):
    records = [base_record(), {**base_record(), "hostname": "host-02"}]
    path = tmp_path / "assets.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    with pytest.raises(ValueError):
        load_inventory(path)


def test_stale_asset_detection():
    fresh = normalize_record(base_record())
    stale = normalize_record({**base_record(), "asset_id": "A-2", "last_seen_days": 60})
    assert [a.asset_id for a in stale_assets([fresh, stale])] == ["A-2"]
