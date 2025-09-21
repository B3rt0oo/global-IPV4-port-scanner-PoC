 # Global IPv4 Port Scanner (PoC)

  Authorized IPv4 port‑scanner PoC. Discovers open ports with masscan, verifies services with nmap -sV, and
  stores results in PostgreSQL or SQLite with full audit logs. Supports sharding, rate limits, blocklists,
  dry‑run, fixture‑based demo mode, and CSV/NDJSON exports.

  ## Features

  - Fast discovery (masscan) → service verification (nmap -sV)
  - Safety rails: required authorization file, blocklist, kill switch
  - Dry‑run and demo mode (no network) for safe testing
  - Storage: PostgreSQL (preferred) or SQLite
  - Exports: findings and audit logs to CSV and NDJSON

  ## Safety

  - Only scan targets with explicit, written authorization
  - Keep conservative rates; respect blocklists and maintenance windows
  - Every attempted input and probe is recorded for auditability

  ## Requirements

  - Python 3.9+
  - Real scans: masscan and nmap installed and in PATH
  - Database: PostgreSQL DSN (optional) or SQLite file path

  ## Quickstart (Demo — no network)

  1. Create an auth file:
      - Create AUTH.txt with the word: AUTHORIZED
  2. Create targets.txt with a few IPs (one per line).
  3. Run:
      - python Global_IPV4_Port_Scanner.py --targets targets.txt --auth AUTH.txt --sqlite demo.db --out-dir
  out --demo
  4. Check out/ for:
      - findings.csv / findings.ndjson
      - attempted_inputs.* and attempted_probes.* (audit logs)

  ## Real Run (Authorized)

  - Example (SQLite):
      - python Global_IPV4_Port_Scanner.py --targets targets.txt --auth AUTH.txt --rate 10000 --nmap-
  concurrency 8 --retries 0 --out-dir out
  - Example (PostgreSQL):
      - python Global_IPV4_Port_Scanner.py --targets targets.txt --auth AUTH.txt --postgres-dsn "postgresql://
  user:pass@host:5432/db" --rate 10000 --out-dir out

  ## Common Flags

  - --targets FILE: IPs/CIDRs/hostnames (one per line)
  - --auth FILE: authorization file (must contain “AUTHORIZED” in PoC)
  - --ports CSV/RANGES: e.g. 80,443 or 1-65535 or all
  - --rate N: masscan packets/sec (default 10000)
  - --nmap-concurrency N: parallel nmap workers
  - --dry-run: print commands; don’t scan
  - --demo: fixture-based demo; no subprocesses/network
  - --postgres-dsn / --sqlite: DB destination
  - --out-dir DIR: write CSV/NDJSON exports here

  ## Outputs

  - findings: ip, port, proto, state, service, product, version, discovered_by, timestamp
  - attempted_inputs: each target fed into the pipeline
  - attempted_probes: each (ip,port) probe with reply/no‑reply and status

  ## Legal

  Use only with explicit authorization. Scanning without permission may be illegal and disruptive.