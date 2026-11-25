"""Real measurements only. KDF, record crypto, and HTTPS round-trip reported separately."""

import argparse
import importlib.metadata
import json
import os
import platform
import ssl
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from client.api import VaultAPI
from client.crypto import derive_key, generate_key, encrypt_record, decrypt_record, canonical
from scripts.dummy_data import MASTER_PASSPHRASE, RECORDS


def measure(function, count):
    function()  # one untimed warmup
    values = []
    for _ in range(count):
        start = time.perf_counter_ns()
        function()
        values.append((time.perf_counter_ns() - start) / 1e6)
    ordered = sorted(values)
    return {
        "samples": count,
        "unit": "ms",
        "min": min(values),
        "median": statistics.median(values),
        "mean": statistics.mean(values),
        "p95": ordered[min(count - 1, int(count * 0.95))],
        "max": max(values),
        "raw_ms": values,
    }


def run(kdf_samples=10, record_samples=1000, network_samples=20, server=None, ca=None):
    key, salt = generate_key(), os.urandom(16)
    uid, vid, rid = (str(uuid4()) for _ in range(3))
    plain = RECORDS[0]
    record = encrypt_record(key, uid, vid, rid, 1, plain)
    cpu = platform.processor()
    if not cpu and Path("/proc/cpuinfo").exists():
        cpu = next(
            (
                s.split(":", 1)[1].strip()
                for s in Path("/proc/cpuinfo").read_text().splitlines()
                if s.startswith("model name")
            ),
            "unknown",
        )
    result = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "machine": {
            "os": platform.platform(),
            "architecture": platform.machine(),
            "cpu": cpu,
            "logical_cpu_count": os.cpu_count(),
            "python": platform.python_version(),
            "python_openssl": ssl.OPENSSL_VERSION,
            "cryptography": importlib.metadata.version("cryptography"),
        },
        "method": "One untimed warmup per operation; serial perf_counter_ns; shared machine, no CPU isolation; p95 nearest upper index.",
        "record_serialized_bytes": len(canonical(plain.model_dump())),
        "kdf_pbkdf2_sha256_600000": measure(lambda: derive_key(MASTER_PASSPHRASE, salt, 600000), kdf_samples),
        "record_encrypt_with_validation_serialization": measure(
            lambda: encrypt_record(key, uid, vid, rid, 1, plain), record_samples
        ),
        "record_decrypt_with_validation_deserialization": measure(
            lambda: decrypt_record(key, uid, vid, record), record_samples
        ),
    }
    if server:
        api = VaultAPI(server, ca)
        try:
            result["https_health_roundtrip_warm_connection"] = measure(
                lambda: api.request("GET", "/health"), network_samples
            )
            result["observed_tls"] = api.tls_info
            result["network_scope"] = server + " (includes HTTP processing; not pure wire latency)"
        finally:
            api.close()
    else:
        result["network_status"] = "Not measured: no HTTPS server supplied."
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--kdf-samples", type=int, default=10)
    parser.add_argument("--record-samples", type=int, default=1000)
    parser.add_argument("--network-samples", type=int, default=20)
    parser.add_argument("--server")
    parser.add_argument("--ca")
    parser.add_argument("--out", default="evidence/benchmark.json")
    args = parser.parse_args()
    if not all(1 <= n <= 100000 for n in (args.kdf_samples, args.record_samples, args.network_samples)):
        parser.error("Sample counts must be 1–100000")
    report = run(args.kdf_samples, args.record_samples, args.network_samples, args.server, args.ca)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Measurements saved to {args.out}; no estimated values substituted.")
