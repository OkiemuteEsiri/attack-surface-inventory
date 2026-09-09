import json
from pathlib import Path
from typing import Iterable, List

from .models import Asset


REQUIRED_FIELDS = {
    "asset_id", "hostname", "asset_type", "owner", "business_service",
    "criticality", "internet_exposed", "environment", "operating_system",
    "last_seen_days"
}


def normalize_record(record: dict) -> Asset:
    missing = sorted(REQUIRED_FIELDS - set(record))
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(missing)}")

    criticality = int(record["criticality"])
    if criticality not in range(1, 6):
        raise ValueError("criticality must be an integer from 1 to 5")

    last_seen_days = int(record["last_seen_days"])
    if last_seen_days < 0:
        raise ValueError("last_seen_days cannot be negative")

    return Asset(
        asset_id=str(record["asset_id"]).strip(),
        hostname=str(record["hostname"]).strip().lower(),
        asset_type=str(record["asset_type"]).strip().lower(),
        owner=str(record["owner"]).strip(),
        business_service=str(record["business_service"]).strip(),
        criticality=criticality,
        internet_exposed=bool(record["internet_exposed"]),
        environment=str(record["environment"]).strip().lower(),
        operating_system=str(record["operating_system"]).strip(),
        last_seen_days=last_seen_days,
        tags=sorted(set(record.get("tags", []))),
        vulnerability_count=max(0, int(record.get("vulnerability_count", 0))),
        critical_vulnerability_count=max(0, int(record.get("critical_vulnerability_count", 0))),
        kev_count=max(0, int(record.get("kev_count", 0))),
        eol=bool(record.get("eol", False)),
        edr_present=record.get("edr_present"),
    )


def load_inventory(path: str | Path) -> List[Asset]:
    records = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError("inventory file must contain a JSON array")
    assets = [normalize_record(record) for record in records]
    ids = [asset.asset_id for asset in assets]
    if len(ids) != len(set(ids)):
        raise ValueError("asset_id values must be unique")
    return assets


def stale_assets(assets: Iterable[Asset], threshold_days: int = 30) -> List[Asset]:
    return [asset for asset in assets if asset.last_seen_days > threshold_days]
