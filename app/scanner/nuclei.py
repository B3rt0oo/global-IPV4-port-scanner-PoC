from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Tuple

from app.logging_setup import get_logger

log = get_logger(__name__)


async def run_nuclei(urls: List[str], templates: List[str] | None = None, dry_run: bool = False) -> Tuple[List[Dict], bool, str]:
    out_jsonl = Path("/tmp") / f"nuclei-{abs(hash(tuple(urls))) % (10**8)}.jsonl"
    cmd = ["nuclei", "-silent", "-jsonl", "-o", str(out_jsonl)]
    for u in urls:
        cmd.extend(["-u", u])
    if templates:
        for t in templates:
            cmd.extend(["-t", t])

    log.info("nuclei_cmd", cmd=" ".join(cmd), count=len(urls))
    if dry_run:
        return [], True, ""

    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    err = stderr.decode(errors="ignore")
    if proc.returncode not in (0, 1):
        log.warning("nuclei_exit", code=proc.returncode)

    findings: List[Dict] = []
    try:
        if out_jsonl.exists():
            for line in out_jsonl.read_text(errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    findings.append(json.loads(line))
                except Exception:
                    pass
            out_jsonl.unlink(missing_ok=True)
    except Exception as e:
        log.error("nuclei_parse_failed", error=str(e))
    return findings, proc.returncode in (0, 1), err

