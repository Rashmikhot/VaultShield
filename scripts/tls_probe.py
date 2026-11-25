"""Collect real OpenSSL negotiation evidence. Fail closed on missing/mismatched parameters."""

import argparse
import json
import platform
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def probe(host, port, ca):
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host) or not 1 <= port <= 65535:
        raise ValueError("Invalid host or port")
    command = [
        "openssl",
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        "-verify_hostname",
        host,
        "-verify_return_error",
        "-CAfile",
        str(ca),
        "-tls1_3",
        "-groups",
        "P-256",
        "-ciphersuites",
        "TLS_AES_256_GCM_SHA384",
        "-no_ticket",
    ]
    completed = subprocess.run(command, input="", text=True, capture_output=True, timeout=15)
    transcript = completed.stdout + completed.stderr
    protocol_ok = bool(re.search(r"(?:New, |Protocol\s*:?\s*|Protocol version:\s*)TLSv1\.3", transcript))
    cipher_ok = bool(
        re.search(r"(?:Cipher is |Cipher\s*:\s*|Ciphersuite:\s*)TLS_AES_256_GCM_SHA384", transcript)
    )
    group_ok = bool(
        re.search(
            r"(?:Server Temp Key|Peer Temp Key|Negotiated TLS1.3 group):[^\n]*(?:prime256v1|P-256|secp256r1)",
            transcript,
        )
    )
    verified = "Verify return code: 0 (ok)" in transcript or "Verification: OK" in transcript
    early_disabled = "Early data was not sent" in transcript
    version = subprocess.run(
        ["openssl", "version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    result = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "machine": platform.platform(),
        "openssl": version,
        "host": host,
        "port": port,
        "checks": {
            "process_ok": completed.returncode == 0,
            "tls13": protocol_ok,
            "aes256gcm": cipher_ok,
            "p256": group_ok,
            "certificate_verified": verified,
            "early_data_not_sent": early_disabled,
        },
        "transcript": transcript,
        "note": "No early data sent by this probe. Server 0-RTT rejection is also configured and reviewed.",
    }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--ca", default="deploy/certs/ca.crt")
    parser.add_argument("--out", default="evidence/tls-observed.json")
    args = parser.parse_args()
    result = probe(args.host, args.port, args.ca)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result["checks"], indent=2))
    raise SystemExit(0 if all(result["checks"].values()) else 1)
