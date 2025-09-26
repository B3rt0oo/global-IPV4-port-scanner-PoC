from __future__ import annotations

import argparse
import asyncio
import os
import random
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple

import httpx
import yaml

from app.logging_setup import setup_logging, get_logger


log = get_logger("scheduler")


@dataclass
class Job:
    name: str
    interval: float  # seconds
    targets: List[str]
    ports_spec: str
    auth_path: Optional[str] = None
    demo: bool = False
    dry_run: bool = False
    api_url: Optional[str] = None
    api_key: Optional[str] = None
    # batching
    batch_size: int = 25
    initial_delay: float = 0.0
    targets_file: Optional[str] = None


@dataclass
class Config:
    api_url: str
    api_key: str
    jobs: List[Job]


def parse_duration(s: str) -> float:
    s = s.strip().lower()
    # support Go-like durations minimally: 300ms, 10s, 5m, 1h
    if s.endswith("ms"):
        return float(s[:-2]) / 1000.0
    mult = 1.0
    if s.endswith("s"):
        mult = 1.0
        s = s[:-1]
    elif s.endswith("m"):
        mult = 60.0
        s = s[:-1]
    elif s.endswith("h"):
        mult = 3600.0
        s = s[:-1]
    return float(s) * mult


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    api_url = os.getenv("API_URL", (raw.get("api", {}) or {}).get("url") or raw.get("api_url") or "http://api:8080")
    api_key = os.getenv("API_KEY", (raw.get("api", {}) or {}).get("api_key") or raw.get("api_key") or "")
    jobs_raw = raw.get("jobs") or []
    jobs: List[Job] = []
    for j in jobs_raw:
        name = j.get("name")
        if not name:
            raise ValueError("job.name is required")
        interval_s = parse_duration(str(j.get("interval", "1h")))
        targets = list(j.get("targets") or [])
        # optional targets file
        tf = j.get("targets_file")
        if tf:
            with open(tf, "r", encoding="utf-8") as fh:
                for line in fh:
                    s = line.strip()
                    if s and not s.startswith("#"):
                        targets.append(s)
        if not targets:
            raise ValueError(f"job {name}: targets required")
        ports_spec = str(j.get("ports_spec") or "1-1024")
        jobs.append(Job(
            name=name,
            interval=interval_s,
            targets=targets,
            ports_spec=ports_spec,
            auth_path=j.get("auth_path"),
            demo=bool(j.get("demo", False)),
            dry_run=bool(j.get("dry_run", False)),
            api_url=j.get("api_url"),
            api_key=j.get("api_key"),
            batch_size=int(j.get("batch_size", 25)),
            initial_delay=parse_duration(str(j.get("initial_delay", "0s"))) if j.get("initial_delay") else 0.0,
            targets_file=tf,
        ))
    return Config(api_url=api_url, api_key=api_key, jobs=jobs)


async def post_scan(client: httpx.AsyncClient, url: str, api_key: str, body: Dict[str, Any]) -> Optional[str]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    r = await client.post(url + "/scans", json=body, headers=headers, timeout=30.0)
    if r.status_code // 100 != 2:
        log.error("post_failed", status=r.status_code, text=r.text[:300])
        return None
    data = r.json()
    return data.get("scan_id")


async def run_job(cfg: Config, j: Job, stop: asyncio.Event):
    api_url = j.api_url or cfg.api_url
    api_key = j.api_key or cfg.api_key
    # Order targets fairly by /24 buckets, then chunk into batches
    def prefix24(t: str) -> str:
        try:
            import ipaddress
            ip = ipaddress.ip_address(t)
            if isinstance(ip, ipaddress.IPv4Address):
                parts = t.split('.')
                return '.'.join(parts[:3]) + '.0/24'
        except Exception:
            pass
        return 'misc'

    buckets: Dict[str, List[str]] = {}
    for t in j.targets:
        buckets.setdefault(prefix24(t), []).append(t)
    order: List[str] = []
    # round-robin draw from buckets
    while any(buckets.values()):
        for k in list(buckets.keys()):
            if buckets[k]:
                order.append(buckets[k].pop(0))
    # chunk
    batches: List[List[str]] = [order[i:i+j.batch_size] for i in range(0, len(order), j.batch_size)]
    if not batches:
        batches = [order]

    async with httpx.AsyncClient() as client:
        # optional initial delay before first batch
        if j.initial_delay > 0:
            try:
                await asyncio.wait_for(stop.wait(), timeout=j.initial_delay)
                return
            except asyncio.TimeoutError:
                pass

        batch_index = 0
        # immediate first batch
        cur = batches[batch_index]
        batch_index = (batch_index + 1) % len(batches)
        scan_id = await post_scan(client, api_url, api_key, {
            "targets": cur,
            "ports_spec": j.ports_spec,
            "auth_path": j.auth_path,
            "demo": j.demo,
            "dry_run": j.dry_run,
        })
        if scan_id:
            log.info("scan_enqueued", job=j.name, batch=len(cur), scan_id=scan_id)
        else:
            log.warning("scan_enqueue_failed", job=j.name, batch=len(cur))

        # loop
        while not stop.is_set():
            # jitter 0-5% to avoid thundering herd
            jitter = 1.0 + random.uniform(-0.05, 0.05)
            wait_s = max(1.0, j.interval * jitter)
            try:
                await asyncio.wait_for(stop.wait(), timeout=wait_s)
                break
            except asyncio.TimeoutError:
                pass

            cur = batches[batch_index]
            batch_index = (batch_index + 1) % len(batches)
            scan_id = await post_scan(client, api_url, api_key, {
                "targets": cur,
                "ports_spec": j.ports_spec,
                "auth_path": j.auth_path,
                "demo": j.demo,
                "dry_run": j.dry_run,
            })
            if scan_id:
                log.info("scan_enqueued", job=j.name, batch=len(cur), scan_id=scan_id)
            else:
                log.warning("scan_enqueue_failed", job=j.name, batch=len(cur))


async def main_async(path: str):
    setup_logging(os.getenv("LOG_LEVEL", "INFO"))
    cfg = load_config(path)
    stop = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (asyncio.CancelledError,):
        pass
    # handle signals
    for sig in ("SIGINT", "SIGTERM"):
        try:
            loop.add_signal_handler(getattr(__import__('signal'), sig), stop.set)
        except Exception:
            # not available on some platforms
            pass

    tasks = [asyncio.create_task(run_job(cfg, j, stop)) for j in cfg.jobs]
    await asyncio.gather(*tasks)


def main():
    ap = argparse.ArgumentParser(description="Scheduler to trigger scans periodically")
    ap.add_argument("--config", default=os.getenv("SCHEDULE_CONFIG", "/config/schedules.yaml"), help="Path to schedules YAML/JSON")
    args = ap.parse_args()
    asyncio.run(main_async(args.config))


if __name__ == "__main__":
    main()
