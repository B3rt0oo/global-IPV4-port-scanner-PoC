from __future__ import annotations

import asyncio
from typing import Optional, Tuple

from app.logging_setup import get_logger

log = get_logger(__name__)


def parse_nmap_xml(xml_text: str, target_port: int):
    import xml.etree.ElementTree as ET

    state = service = product = version = None
    try:
        root = ET.fromstring(xml_text)
        for host in root.findall("host"):
            ports = host.find("ports")
            if not ports:
                continue
            for port in ports.findall("port"):
                try:
                    pnum = int(port.get("portid", "0"))
                except Exception:
                    continue
                if pnum != target_port:
                    continue
                st = port.find("state")
                if st is not None:
                    state = st.get("state")
                svc = port.find("service")
                if svc is not None:
                    service = svc.get("name")
                    product = svc.get("product")
                    version = svc.get("version")
    except Exception:
        pass
    return state, service, product, version


async def run_nmap_probe(ip: str, port: int, timeout: str, dry_run: bool):
    cmd = [
        "nmap",
        "-sV",
        "-p",
        str(port),
        "--host-timeout",
        timeout,
        "-Pn",
        "-oX",
        "-",
        ip,
    ]
    log.info("nmap_cmd", cmd=" ".join(cmd))
    if dry_run:
        return None, None, None, None, True, ""

    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    errtext = stderr.decode(errors="ignore")
    if proc.returncode not in (0, 1):
        log.warning("nmap_exit", code=proc.returncode)
    xml_out = stdout.decode(errors="ignore")
    st, s, pr, v = parse_nmap_xml(xml_out, port)
    return st, s, pr, v, proc.returncode in (0, 1), errtext

