from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Asset:
    asset_id: str
    hostname: str
    asset_type: str
    owner: str
    business_service: str
    criticality: int
    internet_exposed: bool
    environment: str
    operating_system: str
    last_seen_days: int
    tags: List[str] = field(default_factory=list)
    vulnerability_count: int = 0
    critical_vulnerability_count: int = 0
    kev_count: int = 0
    eol: bool = False
    edr_present: Optional[bool] = None


@dataclass(frozen=True)
class ExposureFinding:
    asset_id: str
    score: int
    tier: str
    reasons: List[str]
    data_quality_flags: List[str]
    remediation_priority: str
