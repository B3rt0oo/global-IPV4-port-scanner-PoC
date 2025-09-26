from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional, List


def _getenv(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v is not None else default


def _getint(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def _getbool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "y", "on")


@dataclass
class KafkaConfig:
    enabled: bool = _getbool("KAFKA_ENABLED", False)
    bootstrap_servers: str = _getenv("KAFKA_BOOTSTRAP", "localhost:9092") or "localhost:9092"
    topic_findings: str = _getenv("KAFKA_TOPIC_FINDINGS", "scanner.findings") or "scanner.findings"
    topic_events: str = _getenv("KAFKA_TOPIC_EVENTS", "scanner.events") or "scanner.events"


@dataclass
class ElasticConfig:
    enabled: bool = _getbool("ES_ENABLED", True)
    url: str = _getenv("ES_URL", "http://localhost:9200") or "http://localhost:9200"
    username: Optional[str] = _getenv("ES_USERNAME")
    password: Optional[str] = _getenv("ES_PASSWORD")
    index_findings: str = _getenv("ES_INDEX_FINDINGS", "scanner-findings") or "scanner-findings"
    index_events: str = _getenv("ES_INDEX_EVENTS", "scanner-events") or "scanner-events"


@dataclass
class OTelConfig:
    enabled: bool = _getbool("OTEL_ENABLED", True)
    endpoint: str = _getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317") or "http://localhost:4317"
    service_name: str = _getenv("OTEL_SERVICE_NAME", "globalscanner") or "globalscanner"
    log_correlation: bool = _getbool("OTEL_LOGS_ASSOCIATE_TRACES", True)


@dataclass
class RuntimeConfig:
    # scanning
    masscan_rate: int = _getint("SCAN_MASSCAN_RATE", 10000)
    masscan_wait: int = _getint("SCAN_MASSCAN_WAIT", 10)
    shard_size: int = _getint("SCAN_SHARD_SIZE", 256)
    nmap_concurrency: int = _getint("SCAN_NMAP_CONCURRENCY", 8)
    nmap_timeout: str = _getenv("SCAN_NMAP_TIMEOUT", "45s") or "45s"
    retries: int = _getint("SCAN_RETRIES", 2)
    backoff: float = float(os.getenv("SCAN_BACKOFF", "0.5"))
    max_backoff: float = float(os.getenv("SCAN_MAX_BACKOFF", "8"))
    concurrent_shards: int = _getint("SCAN_CONCURRENT_SHARDS", 1)
    http_user_agents: List[str] = field(
        default_factory=lambda: (
            (os.getenv("HTTP_USER_AGENTS") or "Mozilla/5.0,Chrome/117,Safari/605").split(",")
        )
    )
    proxies_file: Optional[str] = _getenv("HTTP_PROXIES_FILE")
    # safety
    require_auth: bool = _getbool("SCAN_REQUIRE_AUTH", True)
    blocklist_file: Optional[str] = _getenv("SCAN_BLOCKLIST")
    demo: bool = _getbool("SCAN_DEMO", False)
    dry_run: bool = _getbool("SCAN_DRY_RUN", False)
    # profile
    profile: Optional[str] = _getenv("SCAN_PROFILE")
    # adaptive controller
    adaptive: bool = _getbool("SCAN_ADAPTIVE", True)
    rate_min: int = _getint("SCAN_RATE_MIN", 100)
    rate_decay_pct: int = _getint("SCAN_RATE_DECAY_PCT", 30)  # reduce by pct on sustained failures


@dataclass
class AppConfig:
    kafka: KafkaConfig = field(default_factory=KafkaConfig)
    elastic: ElasticConfig = field(default_factory=ElasticConfig)
    otel: OTelConfig = field(default_factory=OTelConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)


def load_config() -> AppConfig:
    cfg = AppConfig()
    # Apply politeness profile overrides if requested
    prof = (cfg.runtime.profile or "").strip().lower()
    if prof in ("low", "medium", "high"):
        if prof == "low":
            cfg.runtime.masscan_rate = 200
            cfg.runtime.concurrent_shards = 1
            cfg.runtime.shard_size = 64
            cfg.runtime.nmap_concurrency = 1
            cfg.runtime.nmap_timeout = "30s"
            cfg.runtime.retries = 0
        elif prof == "medium":
            cfg.runtime.masscan_rate = 500
            cfg.runtime.concurrent_shards = 1
            cfg.runtime.shard_size = 64
            cfg.runtime.nmap_concurrency = 2
            cfg.runtime.nmap_timeout = "45s"
            cfg.runtime.retries = 0
        else:  # high
            cfg.runtime.masscan_rate = 1000
            cfg.runtime.concurrent_shards = 2
            cfg.runtime.shard_size = 128
            cfg.runtime.nmap_concurrency = 4
            cfg.runtime.nmap_timeout = "60s"
            cfg.runtime.retries = 1
    return cfg
