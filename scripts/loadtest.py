#!/usr/bin/env python3
"""Test de carga con trabajo REAL para CERBERUS-LOCAL.

- Pipeline: genera N procesos sintéticos (3 eventos c/u) por el pipeline real
  (EventBus -> Correlator -> RuleEngine -> DetectionPipeline -> ResponseEngine en
  dry_run, SQLite real). Mide throughput de eventos, findings y acciones.
- API (--api): lanza el dashboard y dispara R peticiones concurrentes a /api/summary,
  midiendo throughput y latencia p50/p95.

Uso:
    python scripts/loadtest.py --pids 1000
    python scripts/loadtest.py --pids 500 --api --requests 500 --concurrency 16
"""
from __future__ import annotations

import argparse
import asyncio
import http.client
import logging
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cerberus.core.config import load_config
from cerberus.dashboard.loadgen import run_load
from cerberus.dashboard.server import DashboardServer


def _quiet_logs() -> None:
    logging.getLogger("cerberus").setLevel(logging.ERROR)
    for name in logging.root.manager.loggerDict:
        if name.startswith("cerberus"):
            logging.getLogger(name).setLevel(logging.ERROR)


def _pipeline_load(pids: int, mode: str) -> None:
    with tempfile.TemporaryDirectory() as td:
        res = asyncio.run(run_load(Path(td), n_pids=pids, mode=mode))
    print("=== CARGA: pipeline (trabajo real, dry_run) ===")
    print(f"  procesos sintéticos : {pids}")
    print(f"  eventos procesados  : {res.events}")
    print(f"  findings generados  : {res.findings}")
    print(f"  acciones registradas: {res.actions_logged}")
    print(f"  tiempo              : {res.elapsed_s} s")
    print(f"  throughput          : {res.events_per_s} eventos/s")


def _api_load(requests: int, concurrency: int) -> None:
    with tempfile.TemporaryDirectory() as td:
        cfg_file = Path(td) / "c.yml"
        cfg_file.write_text(
            f"""
mode: dry_run
host_name: LOAD
paths:
  data_dir: {Path(td).as_posix()}
  events_db: {(Path(td) / 'e.db').as_posix()}
  findings_db: {(Path(td) / 'f.db').as_posix()}
  actions_db: {(Path(td) / 'a.db').as_posix()}
  reports_dir: {(Path(td) / 'r').as_posix()}
  log_file: {(Path(td) / 'l.log').as_posix()}
collectors: {{proc: {{enabled: true, poll_interval_seconds: 1.0}}}}
dashboard: {{enabled: true, host: "127.0.0.1", port: 0, refresh_seconds: 5}}
reporting: {{interval_seconds: 60, retention_days: 1}}
""",
            encoding="utf-8",
        )
        cfg = load_config(cfg_file)
        server = DashboardServer(cfg)
        host, port = server.start()
        import threading
        threading.Thread(target=server.serve_forever, daemon=True).start()

        def one() -> tuple[int, float]:
            t0 = time.perf_counter()
            try:
                conn = http.client.HTTPConnection(host, port, timeout=10)
                conn.request("GET", "/api/summary")
                r = conn.getresponse()
                r.read()
                conn.close()
                status = r.status
            except OSError:
                # Una conexión fallida (timeout/puerto efímero en loopback Windows) se
                # contabiliza como fallo en vez de abortar toda la corrida.
                status = 0
            return status, (time.perf_counter() - t0) * 1000.0

        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            results = list(pool.map(lambda _: one(), range(requests)))
        elapsed = time.perf_counter() - start
        server.stop()

    codes = [c for c, _ in results]
    lat = sorted(ms for _, ms in results)
    ok = sum(1 for c in codes if c == 200)
    p50 = lat[len(lat) // 2]
    p95 = lat[min(len(lat) - 1, int(len(lat) * 0.95))]
    print("=== CARGA: API del dashboard (HTTP real) ===")
    print(f"  peticiones          : {requests} (concurrencia {concurrency})")
    print(f"  200 OK              : {ok}/{requests}")
    print(f"  tiempo              : {round(elapsed, 3)} s")
    print(f"  throughput          : {round(requests / elapsed, 1)} req/s")
    print(f"  latencia p50 / p95  : {round(p50, 2)} / {round(p95, 2)} ms")


def main() -> int:
    ap = argparse.ArgumentParser(description="CERBERUS load test (trabajo real)")
    ap.add_argument("--pids", type=int, default=1000, help="procesos sintéticos (3 eventos c/u)")
    ap.add_argument("--mode", default="dry_run")
    ap.add_argument("--api", action="store_true", help="además, carga del API del dashboard")
    ap.add_argument("--requests", type=int, default=500)
    ap.add_argument("--concurrency", type=int, default=16)
    args = ap.parse_args()
    _quiet_logs()
    _pipeline_load(args.pids, args.mode)
    if args.api:
        _api_load(args.requests, args.concurrency)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
