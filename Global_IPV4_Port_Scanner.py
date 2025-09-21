#!/usr/bin/env python3
"""
Global (authorized) IPv4 popular-ports scanner — masscan → nmap → DB

This program merges features:
 - Discovery via masscan (fast, wide) over a curated list of popular ports
 - Verification via nmap -sV to capture service/version details
 - Safety guards (authorization file, dry-run, rate controls, shardable targets)
 - Storage into PostgreSQL (preferred) or SQLite (fallback) with a simple schema

Important: Network scanning can be disruptive and unlawful without prior
authorization. This tool requires an authorization file and refuses to run
without it. Use only for ranges where you have explicit, written permission.

This script does NOT default to scanning the entire IPv4 space. Provide your
authorized target list (IPs, CIDRs, or hostnames) via --targets.
"""

import argparse
import asyncio
import csv
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import ipaddress
import random

try:
    import psycopg2  # type: ignore
    from psycopg2.extras import execute_values  # type: ignore
except Exception:
    psycopg2 = None
    execute_values = None


# ---------------------------
# Popular ports (from Program B)
# ---------------------------
POPULAR_PORTS: List[int] = [
1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37,
42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106,
109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199,
211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389,
406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500,
512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593,
616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705,
711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873,
880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995,
999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025,
1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038,
1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051,
1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064,
1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077,
1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105,
1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123,
1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151,
1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187,
1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247,
1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322,
1328, 1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503,
1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688,
1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805,
1812, 1839, 1840, 1862, 1863, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974,
1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042,
2043, 2045, 2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106,
2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191,
2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2393, 2394,
2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608,
2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909,
2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3011, 3013, 3017,
3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3268, 3269, 3283,
3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3372, 3389,
3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703,
3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871,
3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000,
4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242,
4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899,
4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054,
5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222,
5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510,
5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5672, 5678, 5679, 5718, 5730,
5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900,
5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952,
5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002,
6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123,
6129, 6156, 6346, 6347, 6350, 6355, 6360, 6379, 6389, 6502, 6510, 6543, 6547,
6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779,
6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019,
7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625,
7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000,
8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080,
8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100,
8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333,
8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873,
8888, 8899, 8994, 9000, 9001, 9002, 9009, 9010, 9011, 9040, 9050, 9071, 9080,
9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220,
9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618,
9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999
]

# ---------------------------
# Defaults & globals
# ---------------------------
DEFAULT_MASSCAN_RATE = 10000  # packets per second
DEFAULT_SHARD_SIZE = 256      # targets per masscan shard input list
DEFAULT_NMAP_CONCURRENCY = 8
DEFAULT_NMAP_TIMEOUT = "45s"
DEFAULT_MASSCAN_WAIT = 10
DEFAULT_BATCH_SIZE = 100

# Log levels
LOG_LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
LOG_LEVEL = LOG_LEVELS["INFO"]

def set_log_level(name: str) -> None:
    global LOG_LEVEL
    LOG_LEVEL = LOG_LEVELS.get(name.upper(), LOG_LEVELS["INFO"])

def log(level: str, msg: str) -> None:
    if LOG_LEVELS.get(level.upper(), 100) >= LOG_LEVEL:
        print(msg)

KILL_SWITCH = False


def signal_handler(signum, frame):
    global KILL_SWITCH
    print(f"\n[!] Received signal {signum}. Setting kill switch.")
    KILL_SWITCH = True


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ---------------------------
# Utilities
# ---------------------------
def check_executable_exists(name: str) -> bool:
    return shutil.which(name) is not None


def load_targets(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f"Targets file not found: {path}")
    targets: List[str] = []
    for line in path.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        targets.append(s)
    return targets


def parse_ports_arg(spec: str) -> List[int]:
    """
    Parse ports specification supporting:
    - CSV: "80,443,22"
    - Ranges: "20-25"
    - Keyword: "all" or "1-65535" for full range
    Returns a sorted unique list of ints in [1,65535].
    """
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


def require_authorization_file(auth_path: Path) -> None:
    """
    Guardrail: require a signed authorization file.
    For demonstration, require the file exists and contains the phrase
    "AUTHORIZED". Replace with stronger verification for production usage.
    """
    if not auth_path.exists():
        raise PermissionError(f"Authorization file not found: {auth_path}")
    text = auth_path.read_text(errors="ignore")
    if "AUTHORIZED" not in text:
        raise PermissionError(
            "Authorization file missing required marker. Add 'AUTHORIZED' to proceed."
        )


# ---------------------------
# Database layer
# ---------------------------
@dataclass
class DBConfig:
    postgres_dsn: Optional[str] = None  # e.g., postgresql://user:pass@host:5432/db
    sqlite_path: Optional[str] = None   # e.g., scan_results.db


class ResultStore:
    def __init__(self, cfg: DBConfig):
        self.cfg = cfg
        self.backend = "sqlite"
        self._conn = None
        if cfg.postgres_dsn:
            if psycopg2 is None:
                raise RuntimeError("psycopg2 not installed; cannot use PostgreSQL backend")
            self.backend = "postgres"
            self._conn = psycopg2.connect(cfg.postgres_dsn)
        else:
            path = cfg.sqlite_path or "scan_results.db"
            self._conn = sqlite3.connect(path, check_same_thread=False)
        self._init_schema()

    @property
    def conn(self):
        return self._conn

    def _init_schema(self):
        c = self.conn.cursor()
        if self.backend == "postgres":
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                  id UUID PRIMARY KEY,
                  description TEXT,
                  started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                  id BIGSERIAL PRIMARY KEY,
                  scan_id UUID REFERENCES scans(id),
                  ip INET NOT NULL,
                  port INT NOT NULL,
                  proto TEXT,
                  state TEXT,
                  service TEXT,
                  product TEXT,
                  version TEXT,
                  discovered_by TEXT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            c.execute(
                """
                CREATE INDEX IF NOT EXISTS findings_ip_port_idx
                ON findings(ip, port);
                """
            )
            c.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS findings_scan_ip_port_proto_uniq
                ON findings(scan_id, ip, port, proto);
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS attempted_inputs (
                  id BIGSERIAL PRIMARY KEY,
                  scan_id UUID REFERENCES scans(id),
                  target TEXT NOT NULL,
                  status TEXT,
                  error TEXT,
                  attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS attempted_probes (
                  id BIGSERIAL PRIMARY KEY,
                  scan_id UUID REFERENCES scans(id),
                  ip INET NOT NULL,
                  port INT NOT NULL,
                  proto TEXT,
                  status TEXT,
                  reply BOOLEAN,
                  error TEXT,
                  probed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
        else:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                  id TEXT PRIMARY KEY,
                  description TEXT,
                  started_at TEXT
                );
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id TEXT,
                  ip TEXT NOT NULL,
                  port INTEGER NOT NULL,
                  proto TEXT,
                  state TEXT,
                  service TEXT,
                  product TEXT,
                  version TEXT,
                  discovered_by TEXT,
                  timestamp TEXT
                );
                """
            )
            c.execute(
                """
                CREATE INDEX IF NOT EXISTS findings_ip_port_idx
                ON findings(ip, port);
                """
            )
            c.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS findings_scan_ip_port_proto_uniq
                ON findings(scan_id, ip, port, proto);
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS attempted_inputs (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id TEXT,
                  target TEXT NOT NULL,
                  status TEXT,
                  error TEXT,
                  attempted_at TEXT
                );
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS attempted_probes (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id TEXT,
                  ip TEXT NOT NULL,
                  port INTEGER NOT NULL,
                  proto TEXT,
                  status TEXT,
                  reply INTEGER,
                  error TEXT,
                  probed_at TEXT
                );
                """
            )
        self.conn.commit()

    def create_scan(self, description: str) -> str:
        sid = str(uuid.uuid4())
        c = self.conn.cursor()
        if self.backend == "postgres":
            c.execute(
                "INSERT INTO scans (id, description) VALUES (%s, %s)",
                (sid, description),
            )
        else:
            c.execute(
                "INSERT INTO scans (id, description, started_at) VALUES (?, ?, ?)",
                (sid, description, datetime.utcnow().isoformat() + "Z"),
            )
        self.conn.commit()
        return sid

    def add_finding(
        self,
        scan_id: str,
        ip: str,
        port: int,
        proto: Optional[str],
        state: Optional[str],
        service: Optional[str],
        product: Optional[str],
        version: Optional[str],
        discovered_by: str,
    ) -> None:
        ts = datetime.utcnow().isoformat() + ("Z" if self.backend == "sqlite" else "")
        c = self.conn.cursor()
        if self.backend == "postgres":
            c.execute(
                """
                INSERT INTO findings (scan_id, ip, port, proto, state, service, product, version, discovered_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (scan_id, ip, port, proto)
                DO UPDATE SET
                  state = EXCLUDED.state,
                  service = EXCLUDED.service,
                  product = EXCLUDED.product,
                  version = EXCLUDED.version,
                  discovered_by = EXCLUDED.discovered_by,
                  timestamp = CURRENT_TIMESTAMP
                """,
                (scan_id, ip, port, proto, state, service, product, version, discovered_by),
            )
        else:
            c.execute(
                """
                INSERT INTO findings (scan_id, ip, port, proto, state, service, product, version, discovered_by, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, ip, port, proto)
                DO UPDATE SET
                  state=excluded.state,
                  service=excluded.service,
                  product=excluded.product,
                  version=excluded.version,
                  discovered_by=excluded.discovered_by,
                  timestamp=excluded.timestamp
                """,
                (scan_id, ip, port, proto, state, service, product, version, discovered_by, ts),
            )
        self.conn.commit()

    def record_attempted_input(self, scan_id: str, target: str, status: str, error: Optional[str] = None):
        ts = datetime.utcnow().isoformat() + ("Z" if self.backend == "sqlite" else "")
        c = self.conn.cursor()
        if self.backend == "postgres":
            c.execute(
                "INSERT INTO attempted_inputs (scan_id, target, status, error) VALUES (%s, %s, %s, %s)",
                (scan_id, target, status, error),
            )
        else:
            c.execute(
                "INSERT INTO attempted_inputs (scan_id, target, status, error, attempted_at) VALUES (?, ?, ?, ?, ?)",
                (scan_id, target, status, error, ts),
            )
        self.conn.commit()

    def record_attempted_probe(self, scan_id: str, ip: str, port: int, proto: Optional[str], status: str, reply: bool, error: Optional[str] = None):
        ts = datetime.utcnow().isoformat() + ("Z" if self.backend == "sqlite" else "")
        c = self.conn.cursor()
        if self.backend == "postgres":
            c.execute(
                "INSERT INTO attempted_probes (scan_id, ip, port, proto, status, reply, error) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (scan_id, ip, port, proto, status, reply, error),
            )
        else:
            c.execute(
                "INSERT INTO attempted_probes (scan_id, ip, port, proto, status, reply, error, probed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, ip, port, proto, status, 1 if reply else 0, error, ts),
            )
        self.conn.commit()

    def bulk_add_findings_postgres(self, rows: List[tuple]):
        if self.backend != "postgres":
            return
        if not rows:
            return
        c = self.conn.cursor()
        execute_values(
            c,
            """
            INSERT INTO findings (scan_id, ip, port, proto, state, service, product, version, discovered_by)
            VALUES %s
            ON CONFLICT (scan_id, ip, port, proto)
            DO UPDATE SET
              state = EXCLUDED.state,
              service = EXCLUDED.service,
              product = EXCLUDED.product,
              version = EXCLUDED.version,
              discovered_by = EXCLUDED.discovered_by,
              timestamp = CURRENT_TIMESTAMP
            """,
            rows,
        )
        self.conn.commit()

    def bulk_add_findings_sqlite(self, rows: List[tuple]):
        if self.backend != "sqlite":
            return
        if not rows:
            return
        ts = datetime.utcnow().isoformat() + "Z"
        c = self.conn.cursor()
        payload = [r + (ts,) for r in rows]
        c.executemany(
            """
            INSERT INTO findings (scan_id, ip, port, proto, state, service, product, version, discovered_by, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, ip, port, proto)
            DO UPDATE SET
              state=excluded.state,
              service=excluded.service,
              product=excluded.product,
              version=excluded.version,
              discovered_by=excluded.discovered_by,
              timestamp=excluded.timestamp
            """,
            payload,
        )
        self.conn.commit()

    def bulk_add_findings(self, rows: List[tuple]):
        if self.backend == "postgres":
            self.bulk_add_findings_postgres(rows)
        else:
            self.bulk_add_findings_sqlite(rows)

    # -------- Exports --------
    def export_findings_csv(self, out_dir: Path, scan_id: str):
        path = out_dir / "findings.csv"
        c = self.conn.cursor()
        if self.backend == "postgres":
            c.execute(
                "SELECT ip, port, proto, state, service, product, version, discovered_by, timestamp FROM findings WHERE scan_id=%s",
                (scan_id,),
            )
        else:
            c.execute(
                "SELECT ip, port, proto, state, service, product, version, discovered_by, timestamp FROM findings WHERE scan_id=?",
                (scan_id,),
            )
        rows = c.fetchall()
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip","port","proto","state","service","product","version","discovered_by","timestamp"])
            for r in rows:
                w.writerow(r)

    def export_findings_ndjson(self, out_dir: Path, scan_id: str):
        path = out_dir / "findings.ndjson"
        c = self.conn.cursor()
        if self.backend == "postgres":
            c.execute(
                "SELECT ip, port, proto, state, service, product, version, discovered_by, timestamp FROM findings WHERE scan_id=%s",
                (scan_id,),
            )
        else:
            c.execute(
                "SELECT ip, port, proto, state, service, product, version, discovered_by, timestamp FROM findings WHERE scan_id=?",
                (scan_id,),
            )
        rows = c.fetchall()
        with open(path, "w", encoding="utf-8") as f:
            for r in rows:
                obj = {
                    "ip": r[0],
                    "port": r[1],
                    "proto": r[2],
                    "state": r[3],
                    "service": r[4],
                    "product": r[5],
                    "version": r[6],
                    "discovered_by": r[7],
                    "timestamp": r[8],
                }
                f.write(json.dumps(obj) + "\n")

    def export_attempted_inputs_csv(self, out_dir: Path, scan_id: str):
        path = out_dir / "attempted_inputs.csv"
        c = self.conn.cursor()
        if self.backend == "postgres":
            c.execute(
                "SELECT target, status, error, attempted_at FROM attempted_inputs WHERE scan_id=%s ORDER BY id",
                (scan_id,),
            )
        else:
            c.execute(
                "SELECT target, status, error, attempted_at FROM attempted_inputs WHERE scan_id=? ORDER BY id",
                (scan_id,),
            )
        rows = c.fetchall()
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["target","status","error","attempted_at"])
            for r in rows:
                w.writerow(r)

    def export_attempted_inputs_ndjson(self, out_dir: Path, scan_id: str):
        path = out_dir / "attempted_inputs.ndjson"
        c = self.conn.cursor()
        if self.backend == "postgres":
            c.execute(
                "SELECT target, status, error, attempted_at FROM attempted_inputs WHERE scan_id=%s ORDER BY id",
                (scan_id,),
            )
        else:
            c.execute(
                "SELECT target, status, error, attempted_at FROM attempted_inputs WHERE scan_id=? ORDER BY id",
                (scan_id,),
            )
        rows = c.fetchall()
        with open(path, "w", encoding="utf-8") as f:
            for r in rows:
                obj = {"target": r[0], "status": r[1], "error": r[2], "attempted_at": r[3]}
                f.write(json.dumps(obj) + "\n")

    def export_attempted_probes_csv(self, out_dir: Path, scan_id: str):
        path = out_dir / "attempted_probes.csv"
        c = self.conn.cursor()
        if self.backend == "postgres":
            c.execute(
                "SELECT ip, port, proto, status, reply, error, probed_at FROM attempted_probes WHERE scan_id=%s ORDER BY id",
                (scan_id,),
            )
        else:
            c.execute(
                "SELECT ip, port, proto, status, reply, error, probed_at FROM attempted_probes WHERE scan_id=? ORDER BY id",
                (scan_id,),
            )
        rows = c.fetchall()
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip","port","proto","status","reply","error","probed_at"])
            for r in rows:
                w.writerow(r)

    def export_attempted_probes_ndjson(self, out_dir: Path, scan_id: str):
        path = out_dir / "attempted_probes.ndjson"
        c = self.conn.cursor()
        if self.backend == "postgres":
            c.execute(
                "SELECT ip, port, proto, status, reply, error, probed_at FROM attempted_probes WHERE scan_id=%s ORDER BY id",
                (scan_id,),
            )
        else:
            c.execute(
                "SELECT ip, port, proto, status, reply, error, probed_at FROM attempted_probes WHERE scan_id=? ORDER BY id",
                (scan_id,),
            )
        rows = c.fetchall()
        with open(path, "w", encoding="utf-8") as f:
            for r in rows:
                obj = {
                    "ip": r[0],
                    "port": r[1],
                    "proto": r[2],
                    "status": r[3],
                    "reply": bool(r[4]),
                    "error": r[5],
                    "probed_at": r[6],
                }
                f.write(json.dumps(obj) + "\n")


# ---------------------------
# masscan discovery
# ---------------------------
async def run_masscan_shard(
    shard_targets: List[str],
    ports_csv: str,
    rate: int,
    wait_time: int,
    dry_run: bool,
) -> Tuple[List[Dict], bool, str]:
    if KILL_SWITCH:
        print("[*] Kill switch active; skipping masscan shard.")
        return [], True, ""

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
    print(f"[masscan] cmd: {' '.join(cmd)} (targets: {len(shard_targets)})")
    if dry_run:
        print("[masscan] Dry run; skipping execution.")
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
    errtext = stderr.decode(errors='ignore')
    if proc.returncode != 0:
        print(f"[masscan] non-zero exit {proc.returncode}.")

    results: List[Dict] = []
    try:
        content = Path(out_json.name).read_text(errors="ignore").strip()
        if content:
            # masscan may output array JSON or newline-delimited objects
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
        print(f"[masscan] failed to parse JSON: {e}")

    try:
        os.unlink(targets_path)
        os.unlink(out_json.name)
    except Exception:
        pass

    return results, proc.returncode == 0, errtext


# ---------------------------
# nmap verification (XML parsing)
# ---------------------------
def parse_nmap_xml(xml_text: str, target_port: int) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Return (state, service, product, version) for target_port if present."""
    import xml.etree.ElementTree as ET

    state = service = product = version = None
    try:
        root = ET.fromstring(xml_text)
        for host in root.findall("host"):
            ports = host.find("ports")
            if ports is None:
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


async def run_nmap_probe(
    ip: str, port: int, proto: str, timeout: str, dry_run: bool
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], bool, str]:
    if KILL_SWITCH:
        print("[*] Kill switch active; skipping nmap probe.")
        return None, None, None, None, True, ""

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
    print(f"[nmap] cmd: {' '.join(cmd)}")
    if dry_run:
        return None, None, None, None, True, ""

    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    errtext = stderr.decode(errors='ignore')
    if proc.returncode not in (0, 1):
        print(f"[nmap] exit {proc.returncode}")
    xml_out = stdout.decode(errors="ignore")
    st, s, pr, v = parse_nmap_xml(xml_out, port)
    return st, s, pr, v, proc.returncode in (0, 1), errtext


# ---------------------------
# Demo mode helpers
# ---------------------------
def run_masscan_demo(shard_targets: List[str], ports: List[int]) -> Tuple[List[Dict], bool, str]:
    # Simulate that the first few ports are open for each target.
    chosen = ports[:3] if ports else [80]
    results: List[Dict] = []
    for t in shard_targets:
        # Only simulate for IP-looking targets
        try:
            ipaddress.ip_address(t)
        except ValueError:
            continue
        results.append({
            "ip": t,
            "ports": [{"port": p, "proto": "tcp", "status": "open"} for p in chosen]
        })
    return results, True, ""


def run_nmap_probe_demo(fixtures_dir: Path, ip: str, port: int, proto: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], bool, str]:
    # Load nmap_{port}.xml if present; otherwise, pretend closed/no reply.
    path = fixtures_dir / f"nmap_{port}.xml"
    if path.exists():
        xml_text = path.read_text(encoding="utf-8", errors="ignore")
        st, s, pr, v = parse_nmap_xml(xml_text, port)
        return st or "open", s, pr, v, True, ""
    # default: no reply/closed
    return "closed", None, None, None, True, ""


# ---------------------------
# Orchestration
# ---------------------------
async def orchestrate(
    targets: List[str],
    auth_path: Path,
    ports: List[int],
    rate: int,
    shard_size: int,
    nmap_concurrency: int,
    nmap_timeout: str,
    db: ResultStore,
    dry_run: bool,
    concurrent_shards: int,
    retries: int,
    backoff: float,
    max_backoff: float,
    blocklist_nets: List[ipaddress._BaseNetwork],
    out_dir: Optional[Path],
    export_csv: bool,
    export_json: bool,
    masscan_wait: int = DEFAULT_MASSCAN_WAIT,
    batch_size: int = DEFAULT_BATCH_SIZE,
    demo: bool = False,
    fixtures_dir: Optional[Path] = None,
):
    if not (demo or dry_run):
        if not check_executable_exists("masscan"):
            print("[!] masscan not found in PATH. Install masscan or adjust PATH.")
            return
        if not check_executable_exists("nmap"):
            print("[!] nmap not found in PATH. Install nmap or adjust PATH.")
            return

    require_authorization_file(auth_path)
    scan_id = db.create_scan(description=f"masscan->nmap popular ports; targets={len(targets)}")

    # Build shards (apply blocklist for IPs/CIDRs)
    filtered_targets: List[str] = []
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
            # hostname → keep
            pass
        filtered_targets.append(t)

    shards: List[List[str]] = [filtered_targets[i : i + shard_size] for i in range(0, len(filtered_targets), shard_size)]
    log("INFO", f"[*] Targets: {len(targets)} (filtered={len(filtered_targets)}); shards: {len(shards)} (shard_size={shard_size})")

    ports_csv = ",".join(str(p) for p in ports)

    # Queue for nmap tasks
    nmap_q: asyncio.Queue[Tuple[str, int, str, str]] = asyncio.Queue()

    async def masscan_producer(shards_slice: List[List[str]]):
        for shard in shards_slice:
            if KILL_SWITCH:
                break
            # retry masscan shard on failure with backoff
            attempt = 0
            while True:
                if demo:
                    results, ok, errtext = run_masscan_demo(shard, ports)
                else:
                    results, ok, errtext = await run_masscan_shard(shard, ports_csv, rate, masscan_wait, dry_run)
                for t in shard:
                    db.record_attempted_input(scan_id, t, status=("ok" if ok else "error"), error=(None if ok else (errtext[:512] or "masscan failed")))
                if ok or attempt >= retries or KILL_SWITCH:
                    break
                attempt += 1
                sleep_s = min(max_backoff, (backoff ** attempt) + random.uniform(0, 1))
                log("WARN", f"[masscan] retry {attempt}/{retries} in {sleep_s:.1f}s")
                await asyncio.sleep(sleep_s)
            for entry in results:
                ip = entry.get("ip")
                for p in entry.get("ports", []):
                    port = int(p.get("port"))
                    proto = str(p.get("proto", "tcp"))
                    await nmap_q.put((ip, port, proto, "masscan"))

    # Control shard concurrency
    if concurrent_shards <= 1:
        await masscan_producer(shards)
    else:
        # slice shards into groups
        groups: List[List[List[str]]] = [shards[i::concurrent_shards] for i in range(concurrent_shards)]
        producers = [asyncio.create_task(masscan_producer(g)) for g in groups]
        await asyncio.gather(*producers)

    log("INFO", f"[*] Masscan queued {nmap_q.qsize()} verification probes. Spawning nmap workers...")

    async def nmap_worker(worker_id: int):
        while not KILL_SWITCH:
            try:
                ip, port, proto, discovered_by = await asyncio.wait_for(nmap_q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                if nmap_q.empty():
                    break
                continue
            except asyncio.CancelledError:
                break
            log("DEBUG", f"[worker-{worker_id}] {ip}:{port}/{proto}")
            attempt = 0
            rows_batch: List[tuple] = []
            while True:
                if demo:
                    state, service, product, version, ok, errtext = run_nmap_probe_demo(fixtures_dir or Path("fixtures"), ip, port, proto)
                else:
                    state, service, product, version, ok, errtext = await run_nmap_probe(ip, port, proto, nmap_timeout, dry_run)
                # Record the probe attempt exactly once (first attempt) or each attempt? Here, record the first only if retries == 0; otherwise record each attempt.
                db.record_attempted_probe(scan_id, ip, port, proto, status=("ok" if ok else "error"), reply=(state == "open" or bool(service) or bool(product) or bool(version)), error=(None if ok else (errtext[:512] or "nmap failed")))
                if ok or attempt >= retries or KILL_SWITCH:
                    break
                attempt += 1
                sleep_s = min(max_backoff, (backoff ** attempt) + random.uniform(0, 1))
                log("WARN", f"[nmap] retry {attempt}/{retries} for {ip}:{port} in {sleep_s:.1f}s")
                await asyncio.sleep(sleep_s)
            rows_batch.append((scan_id, ip, port, proto, (state or "unknown"), service, product, version, discovered_by))
            if len(rows_batch) >= batch_size:
                db.bulk_add_findings(rows_batch)
                rows_batch.clear()
            nmap_q.task_done()

        # Flush remainder for this worker
        if 'rows_batch' in locals() and rows_batch:
            db.bulk_add_findings(rows_batch)

    workers = [asyncio.create_task(nmap_worker(i)) for i in range(nmap_concurrency)]
    await nmap_q.join()
    for w in workers:
        w.cancel()
    await asyncio.gather(*workers, return_exceptions=True)

    # Exports
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        if export_csv:
            db.export_findings_csv(out_dir, scan_id)
            db.export_attempted_inputs_csv(out_dir, scan_id)
            db.export_attempted_probes_csv(out_dir, scan_id)
        if export_json:
            db.export_findings_ndjson(out_dir, scan_id)
            db.export_attempted_inputs_ndjson(out_dir, scan_id)
            db.export_attempted_probes_ndjson(out_dir, scan_id)

    print(f"[*] Scan complete. scan_id={scan_id}")


# ---------------------------
# CLI
# ---------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Authorized global popular-ports scanner (masscan -> nmap -> DB). "
            "Provide targets (IPs/CIDRs/hostnames) and an authorization file."
        )
    )
    p.add_argument("--targets", required=True, help="File with targets (one per line: ip, CIDR, or hostname)")
    p.add_argument("--auth", required=True, help="Authorization file (must contain 'AUTHORIZED' – demo guard)")
    p.add_argument("--rate", type=int, default=DEFAULT_MASSCAN_RATE, help=f"masscan rate pps (default {DEFAULT_MASSCAN_RATE})")
    p.add_argument("--shard-size", type=int, default=DEFAULT_SHARD_SIZE, help=f"Targets per masscan shard (default {DEFAULT_SHARD_SIZE})")
    p.add_argument("--nmap-concurrency", type=int, default=DEFAULT_NMAP_CONCURRENCY, help=f"Concurrent nmap workers (default {DEFAULT_NMAP_CONCURRENCY})")
    p.add_argument("--nmap-timeout", default=DEFAULT_NMAP_TIMEOUT, help=f"nmap host timeout (default {DEFAULT_NMAP_TIMEOUT})")
    p.add_argument("--dry-run", action="store_true", help="Dry run: print planned commands, no scanning")
    p.add_argument("--concurrent-shards", type=int, default=1, help="Number of masscan shards to run concurrently (be polite)")
    p.add_argument("--masscan-wait", type=int, default=DEFAULT_MASSCAN_WAIT, help=f"masscan --wait seconds (default {DEFAULT_MASSCAN_WAIT})")
    p.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help=f"Batch size for DB inserts (default {DEFAULT_BATCH_SIZE})")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG","INFO","WARN","ERROR"], help="Log verbosity level")

    # Ports control
    p.add_argument(
        "--ports",
        default=None,
        help=(
            "CSV of ports to scan. If omitted, uses curated popular ports from Program B."
        ),
    )

    # DB options
    p.add_argument("--postgres-dsn", default=None, help="PostgreSQL DSN, e.g. postgresql://user:pass@host:5432/dbname")
    p.add_argument("--sqlite", default=None, help="SQLite file path (fallback if no PostgreSQL DSN provided)")

    # Blocklist
    p.add_argument("--blocklist", default=None, help="File with IPs/CIDRs to exclude (opt-out)")

    # Retries/backoff
    p.add_argument("--retries", type=int, default=0, help="Retries for masscan/nmap on transient errors (default 0: knock once)")
    p.add_argument("--backoff", type=float, default=1.5, help="Exponential backoff base (default 1.5)")
    p.add_argument("--max-backoff", type=float, default=30.0, help="Maximum backoff seconds (default 30)")

    # Exports
    p.add_argument("--out-dir", default=None, help="Directory to write CSV/NDJSON exports")
    p.add_argument("--no-csv", action="store_true", help="Disable CSV export")
    p.add_argument("--no-json", action="store_true", help="Disable NDJSON export")

    # Shard maker
    p.add_argument("--global-shards", action="store_true", help="Generate IPv4 shards for 0.0.0.0/0 minus reserved ranges and exit")
    p.add_argument("--make-shards", action="store_true", help="Generate CIDR shard files from include/exclude sets and exit")
    p.add_argument("--include-cidrs", default=None, help="Comma-separated CIDRs to include, or @file to read list")
    p.add_argument("--exclude-cidrs", default=None, help="Comma-separated CIDRs to exclude, or @file to read list")
    p.add_argument("--shard-max-addrs", type=int, default=5_000_000, help="Max addresses per shard (CIDR-based)")
    p.add_argument("--out-shards-dir", default="shards", help="Output directory for generated shards")

    # Demo mode
    p.add_argument("--demo", action="store_true", help="Run in fixture/demo mode (no masscan/nmap subprocesses)")
    p.add_argument("--fixtures-dir", default="fixtures", help="Directory containing demo fixtures")

    return p.parse_args()


def main():
    args = parse_args()
    set_log_level(args.log_level)

    # Optional: create shards and exit
    if args.global_shards:
        includes = [ipaddress.ip_network('0.0.0.0/0')]
        excludes = reserved_ipv4_excludes()
        try:
            shard_paths = make_cidr_shards(includes, excludes, args.shard_max_addrs, Path(args.out_shards_dir))
        except Exception as e:
            print(f"[!] Failed to make global shards: {e}")
            sys.exit(1)
        print(f"[*] Wrote {len(shard_paths)} global shard files to {args.out_shards_dir}")
        sys.exit(0)

    if args.make_shards:
        includes = read_cidrs_arg(args.include_cidrs or "")
        excludes = read_cidrs_arg(args.exclude_cidrs or "")
        try:
            shard_paths = make_cidr_shards(includes, excludes, args.shard_max_addrs, Path(args.out_shards_dir))
        except Exception as e:
            print(f"[!] Failed to make shards: {e}")
            sys.exit(1)
        print(f"[*] Wrote {len(shard_paths)} shard files to {args.out_shards_dir}")
        sys.exit(0)

    # Load targets and safety echo
    targets = load_targets(Path(args.targets))
    if not targets:
        print("No targets loaded.")
        sys.exit(1)

    # Safety banner
    log("WARN", "WARNING: This tool performs network scans against provided targets.")
    log("WARN", "Use ONLY with explicit, written authorization for all targets and windows.")
    log("INFO", f"Targets file: {args.targets} (count={len(targets)})")
    log("INFO", f"Authorization file: {args.auth}")
    if args.dry_run:
        log("INFO", "[DRY RUN] No masscan or nmap will be executed.")

    # Build ports list
    ports: List[int]
    if args.ports:
        ports = parse_ports_arg(args.ports)
    else:
        ports = POPULAR_PORTS

    # DB
    db_cfg = DBConfig(postgres_dsn=args.postgres_dsn, sqlite_path=args.sqlite)
    try:
        store = ResultStore(db_cfg)
    except Exception as e:
        print(f"[!] Failed to initialize database: {e}")
        sys.exit(1)

    # Blocklist nets
    blocklist_nets: List[ipaddress._BaseNetwork] = []
    if args.blocklist:
        try:
            for line in Path(args.blocklist).read_text().splitlines():
                s = line.strip()
                if not s or s.startswith('#'):
                    continue
                try:
                    blocklist_nets.append(ipaddress.ip_network(s, strict=False))
                except ValueError:
                    continue
        except Exception as e:
            print(f"[!] Failed to read blocklist: {e}")

    try:
        asyncio.run(
            orchestrate(
                targets=targets,
                auth_path=Path(args.auth),
                ports=ports,
                rate=args.rate,
                shard_size=args.shard_size,
                nmap_concurrency=args.nmap_concurrency,
                nmap_timeout=args.nmap_timeout,
                db=store,
                dry_run=args.dry_run,
                concurrent_shards=args.concurrent_shards,
                retries=args.retries,
                backoff=args.backoff,
                max_backoff=args.max_backoff,
                blocklist_nets=blocklist_nets,
                out_dir=(Path(args.out_dir) if args.out_dir else None),
                export_csv=(not args.no_csv),
                export_json=(not args.no_json),
                masscan_wait=args.masscan_wait,
                batch_size=args.batch_size,
                demo=args.demo,
                fixtures_dir=Path(args.fixtures_dir),
            )
        )
    except PermissionError as pe:
        print(f"[!] Permission error: {pe}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unhandled exception: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

# ---------------------------
# CIDR shard helper utilities
# ---------------------------
def read_cidrs_arg(spec: str) -> List[ipaddress._BaseNetwork]:
    spec = spec.strip()
    if not spec:
        return []
    if spec.startswith('@'):
        path = Path(spec[1:])
        text = path.read_text()
        items = [s.strip() for s in text.splitlines() if s.strip() and not s.strip().startswith('#')]
    else:
        items = [s.strip() for s in spec.split(',') if s.strip()]
    nets: List[ipaddress._BaseNetwork] = []
    for s in items:
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            pass
    return nets


def subtract_excludes(includes: List[ipaddress._BaseNetwork], excludes: List[ipaddress._BaseNetwork]) -> List[ipaddress._BaseNetwork]:
    # Collapse includes first
    work: List[ipaddress._BaseNetwork] = list(ipaddress.collapse_addresses(includes))
    if not excludes:
        return work
    result: List[ipaddress._BaseNetwork] = []
    for inc in work:
        parts = [inc]
        for exc in excludes:
            new_parts: List[ipaddress._BaseNetwork] = []
            for p in parts:
                if p.version != exc.version:
                    new_parts.append(p)
                    continue
                if not p.overlaps(exc):
                    new_parts.append(p)
                else:
                    try:
                        for piece in p.address_exclude(exc):
                            new_parts.append(piece)
                    except ValueError:
                        new_parts.append(p)
            parts = new_parts
        result.extend(parts)
    return list(ipaddress.collapse_addresses(result))


def split_net_to_fit(net: ipaddress._BaseNetwork, max_addrs: int) -> List[ipaddress._BaseNetwork]:
    if net.num_addresses <= max_addrs:
        return [net]
    out: List[ipaddress._BaseNetwork] = []
    queue: List[ipaddress._BaseNetwork] = [net]
    while queue:
        n = queue.pop()
        if n.num_addresses <= max_addrs:
            out.append(n)
            continue
        subs = list(n.subnets(prefixlen_diff=1))
        queue.extend(subs)
    return out


def make_cidr_shards(includes: List[ipaddress._BaseNetwork], excludes: List[ipaddress._BaseNetwork], max_addrs: int, out_dir: Path) -> List[Path]:
    nets = subtract_excludes(includes, excludes)
    current: List[ipaddress._BaseNetwork] = []
    current_sum = 0
    shards: List[List[ipaddress._BaseNetwork]] = []
    for net in nets:
        pieces = split_net_to_fit(net, max_addrs)
        for piece in pieces:
            naddrs = piece.num_addresses
            if current_sum + naddrs > max_addrs and current:
                shards.append(current)
                current = []
                current_sum = 0
            current.append(piece)
            current_sum += naddrs
    if current:
        shards.append(current)

    out_dir.mkdir(parents=True, exist_ok=True)
    paths: List[Path] = []
    for i, shard in enumerate(shards, start=1):
        p = out_dir / f"shard-{i:04d}.txt"
        with open(p, "w", encoding="utf-8") as f:
            for n in shard:
                f.write(str(n) + "\n")
        paths.append(p)
    return paths


def reserved_ipv4_excludes() -> List[ipaddress._BaseNetwork]:
    """RFC-reserved and special-use IPv4 ranges to exclude for global scans."""
    cidrs = [
        '0.0.0.0/8',        # current network
        '10.0.0.0/8',       # RFC1918
        '100.64.0.0/10',    # CGNAT
        '127.0.0.0/8',      # loopback
        '169.254.0.0/16',   # link-local
        '172.16.0.0/12',    # RFC1918
        '192.0.0.0/24',     # IETF Protocol Assignments
        '192.0.2.0/24',     # TEST-NET-1
        '192.168.0.0/16',   # RFC1918
        '198.18.0.0/15',    # benchmarking
        '198.51.100.0/24',  # TEST-NET-2
        '203.0.113.0/24',   # TEST-NET-3
        '224.0.0.0/4',      # multicast
        '240.0.0.0/4',      # reserved
        '255.255.255.255/32',
    ]
    nets: List[ipaddress._BaseNetwork] = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c))
        except ValueError:
            pass
    return nets
