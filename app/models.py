from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanRequest:
    id: str
    description: str
    targets: List[str]
    ports: Optional[List[int]] = None
    auth_path: Optional[str] = None
    demo: bool = False
    dry_run: bool = False


@dataclass
class Finding:
    scan_id: str
    ip: str
    port: int
    proto: Optional[str]
    state: Optional[str]
    service: Optional[str]
    product: Optional[str]
    version: Optional[str]
    discovered_by: str
    nuclei_template: Optional[str] = None
    http_title: Optional[str] = None
    http_screenshot_path: Optional[str] = None
    ts: str = utcnow_iso()

    def to_doc(self) -> Dict[str, Any]:
        d = asdict(self)
        d["@timestamp"] = d.pop("ts")
        return d


@dataclass
class Event:
    scan_id: str
    level: str
    message: str
    data: Optional[Dict[str, Any]] = None
    ts: str = utcnow_iso()

    def to_doc(self) -> Dict[str, Any]:
        d = asdict(self)
        d["@timestamp"] = d.pop("ts")
        return d

