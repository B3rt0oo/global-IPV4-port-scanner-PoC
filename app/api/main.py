from __future__ import annotations

import asyncio
import os
import uuid
from typing import List, Optional

from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel

from app.config import load_config
from app.logging_setup import setup_logging, get_logger
from app.otel import init_otel
from app.kafka_client import KafkaProducer
from app.storage.elasticsearch_store import ElasticStore
from app.orchestrator import Orchestrator, parse_ports_arg


class ScanBody(BaseModel):
    targets: List[str]
    ports: Optional[List[int]] = None
    ports_spec: Optional[str] = None
    description: Optional[str] = None
    auth_path: Optional[str] = None
    demo: Optional[bool] = False
    dry_run: Optional[bool] = False


cfg = load_config()
setup_logging(os.getenv("LOG_LEVEL", "INFO"))
if cfg.otel.enabled:
    init_otel(cfg.otel.service_name, cfg.otel.endpoint)

log = get_logger("api")
es = ElasticStore(cfg.elastic)
kprod = KafkaProducer(cfg.kafka)
orch = Orchestrator(cfg, es, kprod)

app = FastAPI(title="GlobalScanner API", version="0.1.0")


@app.on_event("startup")
async def on_startup():
    await kprod.start()
    log.info("startup")


@app.on_event("shutdown")
async def on_shutdown():
    await kprod.stop()
    log.info("shutdown")


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.post("/scans")
async def create_scan(body: ScanBody, tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    ports = body.ports or (parse_ports_arg(body.ports_spec) if body.ports_spec else None)
    # fire-and-forget background task
    tasks.add_task(
        orch.run_scan,
        targets=body.targets,
        ports=ports,
        auth_path=(os.path.abspath(body.auth_path) if body.auth_path else None),
        scan_id=scan_id,
        demo=bool(body.demo),
        dry_run=bool(body.dry_run),
    )
    log.info("scan_queued", scan_id=scan_id, targets=len(body.targets))
    return {"scan_id": scan_id}

