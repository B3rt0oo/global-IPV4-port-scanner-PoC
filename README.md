 # Global IPv4 Port Scanner (GlobalScanner)

  Authorized IPv4 port‑scanner now modularized and exposed as a REST API.
  Discovers open ports with masscan, verifies services with nmap -sV, enriches with
  Nuclei (vuln templates) and an optional headless browser (Playwright), and ships
  results to Elasticsearch and/or Kafka. Observability via OpenTelemetry (traces,
  metrics) with JSON logs (trace correlation). Docker + Kubernetes manifests included.

  ## Features

  - Fast discovery (masscan) → service verification (nmap -sV)
  - Safety rails: required authorization file, blocklist, kill switch
  - Dry‑run and demo mode (no network) for safe testing
  - Enrichment: Nuclei scan for HTTP endpoints; headless browser title/screenshot
  - Storage & streaming: Elasticsearch (default) and Kafka producer
  - Observability: OpenTelemetry traces + metrics; JSON logs with trace_id/span_id
  - REST API (FastAPI) to trigger scans; Dockerfile and K8s Deployment

  ## Safety

  - Only scan targets with explicit, written authorization
  - Keep conservative rates; respect blocklists and maintenance windows
  - Every attempted input and probe is recorded for auditability

  ## Requirements

  - Python 3.10+
  - Real scans: `masscan`, `nmap`, `nuclei` in PATH
  - Headless browser: Playwright chromium (Docker image includes it)
  - Storage: Elasticsearch 8.x (default), optional Kafka broker

  ## Quickstart (REST API)

  1. Build the Docker image:

      - docker build -t globalscanner:latest .

  2. Run (with defaults: ES at http://localhost:9200, OTEL off):

      - docker run --rm -p 8080:8080 \
        -e ES_ENABLED=true -e ES_URL=http://host.docker.internal:9200 \
        globalscanner:latest

  3. Trigger a scan:

      - curl -X POST http://localhost:8080/scans \
        -H 'Content-Type: application/json' \
        -d '{"targets":["93.184.216.34"], "ports_spec":"80,443", "demo":true}'

  The API responds with `{ "scan_id": "..." }` and processes in background.

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

  ## REST Model

  - POST `/scans` body:
    - `targets`: array of IPs/CIDRs/hostnames
    - `ports`: optional array of ints, or `ports_spec` like `80,443,1-1024`
    - `auth_path`: path mounted in container to an authorization file
    - `demo`/`dry_run`: booleans

  ## Common Env Vars

  - `ES_ENABLED=true` `ES_URL=http://elasticsearch:9200`
  - `KAFKA_ENABLED=true` `KAFKA_BOOTSTRAP=kafka:9092`
  - `OTEL_ENABLED=true` `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317`
  - `LOG_LEVEL=INFO`
  - `SCAN_MASSCAN_RATE=10000` `SCAN_NMAP_CONCURRENCY=8` etc.

  ## Outputs

  - Elasticsearch indices:
    - findings: ip, port, proto, state, service, product, version, http_title, nuclei_template, discovered_by, @timestamp
    - events: lifecycle/status JSON logs
  - Kafka (optional): JSON events on `scanner.findings` and `scanner.events`

  ## Legal

  Use only with explicit authorization. Scanning without permission may be illegal and disruptive.
  ## Notes on the Legacy Script

  The original monolithic `Global_IPV4_Port_Scanner.py` remains for reference.
  The new modules live under `app/` and are served by FastAPI in Docker/K8s.
