from __future__ import annotations

import asyncio
import ipaddress
import random
import uuid
from pathlib import Path
from typing import List, Optional, Tuple

from opentelemetry import trace, metrics
from tenacity import AsyncRetrying, wait_exponential_jitter, stop_after_attempt

from app.config import AppConfig
from app.kafka_client import KafkaProducer
from app.logging_setup import get_logger
from app.models import Finding, Event
from app.scanner.masscan import run_masscan_shard
from app.scanner.nmap import run_nmap_probe
from app.scanner.nuclei import run_nuclei
from app.scanner.browser import fetch_page_title_and_screenshot
from app.storage.elasticsearch_store import ElasticStore

log = get_logger(__name__)
tracer = trace.get_tracer(__name__)
meter = metrics.get_meter(__name__)

metric_findings = meter.create_counter("scanner_findings_total")
metric_tasks = meter.create_counter("scanner_tasks_total")
metric_errors = meter.create_counter("scanner_errors_total")


def parse_ports_arg(spec: str) -> List[int]:
    spec = (spec or "").strip().lower()
    if not spec:
        return []
    if spec == "all" or spec == "1-65535":
        return list(range(1, 65536))
    out: set[int] = set()
    for part in spec.split(','):
        p = part.strip()
        if not p:
            continue
        if '-' in p:
            a, b = p.split('-', 1)
            try:
                start = max(1, int(a))
                end = min(65535, int(b))
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            for v in range(start, end + 1):
                out.add(v)
        else:
            try:
                v = int(p)
            except ValueError:
                continue
            if 1 <= v <= 65535:
                out.add(v)
    return sorted(out)


class Orchestrator:
    def __init__(self, cfg: AppConfig, es: ElasticStore, kprod: KafkaProducer):
        self.cfg = cfg
        self.es = es
        self.kprod = kprod

    async def _maybe_kafka(self, topic: str, payload: dict):
        try:
            await self.kprod.send_json(topic, payload)
        except Exception:
            pass

    def _build_urls(self, ip: str, port: int) -> List[str]:
        urls = []
        if port in (80, 8080):
            urls.append(f"http://{ip}:{port}")
        if port in (443, 8443):
            urls.append(f"https://{ip}:{port}")
        # also try generic http for common web ports
        if port in (8000, 8008, 8081, 9090):
            urls.append(f"http://{ip}:{port}")
        return urls

    async def run_scan(
        self,
        targets: List[str],
        ports: Optional[List[int]],
        auth_path: Optional[Path],
        scan_id: Optional[str] = None,
        demo: bool = False,
        dry_run: bool = False,
    ) -> str:
        scan_id = scan_id or str(uuid.uuid4())
        cfg = self.cfg
        tracer_span = tracer.start_as_current_span("scan")
        with tracer_span:
            log.info("scan_start", scan_id=scan_id, targets=len(targets))
            metric_tasks.add(1, {"task": "scan_start"})

            # Demo mode: simulate findings without external tools
            if demo or self.cfg.runtime.demo:
                demo_ports = ports or [80, 443]
                for t in targets:
                    try:
                        ipaddress.ip_address(t)
                    except ValueError:
                        continue
                    for p in demo_ports[:3]:
                        finding = Finding(
                            scan_id=scan_id,
                            ip=t,
                            port=p,
                            proto="tcp",
                            state="open",
                            service="http" if p in (80, 8080) else ("https" if p in (443, 8443) else None),
                            product=None,
                            version=None,
                            discovered_by="demo",
                        )
                        doc = finding.to_doc()
                        self.es.index_finding(doc)
                        metric_findings.add(1)
                        await self._maybe_kafka(self.cfg.kafka.topic_findings, doc)
                log.info("scan_complete_demo", scan_id=scan_id)
                return scan_id

            # Build shards
            filtered_targets: List[str] = []
            blocklist_nets: List[ipaddress._BaseNetwork] = []
            if cfg.runtime.blocklist_file:
                try:
                    for line in Path(cfg.runtime.blocklist_file).read_text().splitlines():
                        s = line.strip()
                        if not s or s.startswith('#'):
                            continue
                        blocklist_nets.append(ipaddress.ip_network(s, strict=False))
                except Exception:
                    pass

            for t in targets:
                try:
                    if "/" in t:
                        net = ipaddress.ip_network(t, strict=False)
                        if any(net.subnet_of(b) for b in blocklist_nets):
                            continue
                    else:
                        ip = ipaddress.ip_address(t)
                        if any(ip in b for b in blocklist_nets):
                            continue
                except ValueError:
                    pass
                filtered_targets.append(t)

            shard_size = cfg.runtime.shard_size
            shards: List[List[str]] = [filtered_targets[i : i + shard_size] for i in range(0, len(filtered_targets), shard_size)]

            ports_list = ports or []
            ports_csv = ",".join(str(p) for p in ports_list) if ports_list else "1-1024,3306,3389,5432,6379,8080,8443"

            async def process_shard(shard: List[str]):
                results, ok, err = await run_masscan_shard(shard, ports_csv, cfg.runtime.masscan_rate, cfg.runtime.masscan_wait, dry_run)
                if not ok:
                    metric_errors.add(1, {"stage": "masscan"})
                for entry in results:
                    ip = entry.get("ip")
                    for p in entry.get("ports", []):
                        port = int(p.get("port"))
                        proto = p.get("proto", "tcp")
                        await self._verify_and_enrich(scan_id, ip, port, proto, dry_run)

            # Control concurrency across shards
            sem = asyncio.Semaphore(cfg.runtime.concurrent_shards)

            async def sem_task(shard):
                async with sem:
                    await process_shard(shard)

            await asyncio.gather(*(sem_task(s) for s in shards))

            log.info("scan_complete", scan_id=scan_id)
            return scan_id

    async def _verify_and_enrich(self, scan_id: str, ip: str, port: int, proto: str, dry_run: bool):
        cfg = self.cfg
        # anti-ban: small jitter, configurable
        await asyncio.sleep(random.uniform(0.05, 0.25))

        # nmap verification
        with tracer.start_as_current_span("nmap_probe"):
            st, s, pr, v, ok, err = await run_nmap_probe(ip, port, cfg.runtime.nmap_timeout, dry_run)
        if not ok:
            metric_errors.add(1, {"stage": "nmap"})

        finding = Finding(
            scan_id=scan_id,
            ip=ip,
            port=port,
            proto=proto,
            state=st,
            service=s,
            product=pr,
            version=v,
            discovered_by="masscan+nmap",
        )

        # Nuclei enrichment for probable HTTP(s)
        urls = self._build_urls(ip, port)
        nuclei_hits = []
        if urls:
            with tracer.start_as_current_span("nuclei"):
                nuc, ok, err = await run_nuclei(urls, dry_run=dry_run)
                nuclei_hits = nuc or []
                if not ok:
                    metric_errors.add(1, {"stage": "nuclei"})
        if nuclei_hits:
            finding.nuclei_template = ",".join(sorted({h.get("template-id", "") for h in nuclei_hits if h}))

        # headless browser fetch (best-effort)
        if urls:
            with tracer.start_as_current_span("browser"):
                title, screenshot = await fetch_page_title_and_screenshot(urls[0], Path("screenshots"))
                finding.http_title = title
                finding.http_screenshot_path = screenshot

        doc = finding.to_doc()
        self.es.index_finding(doc)
        metric_findings.add(1)
        await self._maybe_kafka(self.cfg.kafka.topic_findings, doc)
