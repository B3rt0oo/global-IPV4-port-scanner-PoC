from __future__ import annotations

import asyncio
import json
import os
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

from app.logging_setup import get_logger

log = get_logger(__name__)


async def run_masscan_shard(shard_targets: List[str], ports_csv: str, rate: int, wait_time: int, dry_run: bool) -> Tuple[List[Dict], bool, str]:
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        tf.write("\n".join(shard_targets))
        tf.flush()
        targets_path = tf.name

    out_json = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    out_json.close()

    cmd = [
        "masscan",
        "-iL",
        targets_path,
        "-p",
        ports_csv,
        "--rate",
        str(rate),
        "--wait",
        str(wait_time),
        "-oJ",
        out_json.name,
    ]
    log.info("masscan_cmd", cmd=" ".join(cmd), targets=len(shard_targets))
    if dry_run:
        try:
            os.unlink(targets_path)
            os.unlink(out_json.name)
        except Exception:
            pass
        return [], True, ""

    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    errtext = stderr.decode(errors="ignore")
    if proc.returncode != 0:
        log.warning("masscan_exit", code=proc.returncode)

    results: List[Dict] = []
    try:
        content = Path(out_json.name).read_text(errors="ignore").strip()
        if content:
            if content.startswith("["):
                parsed = json.loads(content)
            else:
                lines = [l.strip() for l in content.splitlines() if l.strip()]
                parsed = [json.loads(l) for l in lines]
            by_ip = defaultdict(list)
            for entry in parsed:
                ip = entry.get("ip")
                for p in entry.get("ports", []):
                    by_ip[ip].append(p)
            for ip, ports in by_ip.items():
                results.append({"ip": ip, "ports": ports})
    except Exception as e:
        log.error("masscan_parse_failed", error=str(e))
    finally:
        try:
            os.unlink(targets_path)
            os.unlink(out_json.name)
        except Exception:
            pass

    return results, proc.returncode == 0, errtext

