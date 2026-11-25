"""Generate local demo certificates, start the HTTPS API, then open the desktop client."""

import argparse
import datetime as dt
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import webbrowser
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from client.api import VaultAPI, APIError

ROOT = Path(__file__).resolve().parent.parent


def create_certificates(directory):
    """A private demo CA signs a localhost leaf. The CA private key is never saved."""
    directory = Path(directory)
    if directory.exists() and any(directory.iterdir()):
        raise FileExistsError("Refusing to overwrite certificates")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VaultShield Local Demo CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    contents = {
        "ca.crt": ca.public_bytes(serialization.Encoding.PEM),
        "server.crt": leaf.public_bytes(serialization.Encoding.PEM),
        "server.key": server_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    }
    for name, data in contents.items():
        descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)


def ensure_certificates(directory):
    directory = Path(directory)
    if not directory.exists() or not any(directory.iterdir()):
        create_certificates(directory)
    if any(not (directory / name).is_file() for name in ("ca.crt", "server.crt", "server.key")):
        raise RuntimeError("Incomplete demo certificates. See README: certificate renewal.")
    now = dt.datetime.now(dt.timezone.utc)
    for name in ("ca.crt", "server.crt"):
        cert = x509.load_pem_x509_certificate((directory / name).read_bytes())
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise RuntimeError("Demo certificate expired or computer clock is incorrect. See README.")


class InstanceLock:
    def __init__(self, data_dir):
        self.file = None
        self.path = Path(data_dir) / "instance.lock"

    def acquire(self):
        self.file = self.path.open("a+b")
        self.file.seek(0, 2)
        if self.file.tell() == 0:
            self.file.write(b"0")
            self.file.flush()
        self.file.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            self.file = None
            raise RuntimeError("VaultShield is already running. Close the other demo window first.") from None

    def release(self):
        if self.file:
            self.file.close()
            self.file = None


class LocalBackend:
    def __init__(self, data_dir, web_mode=False):
        self.data_dir = Path(data_dir).resolve()
        self.certs = self.data_dir / "certs"
        self.process = None
        self.lock = InstanceLock(self.data_dir)
        self.url = None
        self.web_mode = web_mode

    def __enter__(self):
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock.acquire()
        try:
            if not self.web_mode:
                ensure_certificates(self.certs)
            with socket.socket() as available:
                available.bind(("127.0.0.1", 0))
                port = available.getsockname()[1]
            self.url = f"http://127.0.0.1:{port}" if self.web_mode else f"https://localhost:{port}"
            server_module = "scripts.web_server" if self.web_mode else "scripts.local_server"
            command = [
                sys.executable, "-m", server_module,
                "--data-dir", str(self.data_dir), "--port", str(port),
            ]
            self.process = subprocess.Popen(command, cwd=ROOT)
            deadline = time.monotonic() + 20
            api = None if self.web_mode else VaultAPI(self.url, str(self.certs / "ca.crt"))
            try:
                while time.monotonic() < deadline:
                    if self.process.poll() is not None:
                        raise RuntimeError("The local server could not start. See the console message above.")
                    try:
                        if self.web_mode:
                            with socket.create_connection(("127.0.0.1", port), timeout=1):
                                break
                        else:
                            health = api.request("GET", "/health")
                            if health.get("status") == "ok":
                                break
                    except Exception:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Local web server startup failed. Check firewall settings.")
                self.tls_info = None if self.web_mode else api.tls_info
            finally:
                if api:
                    api.close()
            (self.data_dir / "connection.json").write_text(
                json.dumps(
                    {"url": self.url, "ca": str(self.certs / "ca.crt"), "observed_tls": self.tls_info},
                    indent=2,
                ),
                encoding="utf-8",
            )
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.lock.release()


def self_test():
    from scripts.https_smoke import run

    with tempfile.TemporaryDirectory(prefix="vaultshield-simple-check-") as directory:
        with LocalBackend(directory) as backend:
            result = run(backend.url, str(backend.certs / "ca.crt"))
    print(json.dumps(result, indent=2))
    if not all(result["checks"].values()):
        raise RuntimeError("Demo self-test failed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--self-test", action="store_true", help="Check HTTPS and dummy data in a disposable folder"
    )
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    print("Starting VaultShield Web: local-only FastAPI server.")
    with LocalBackend(ROOT / ".demo-data", web_mode=True) as backend:
        print(f"VaultShield is ready at {backend.url}")
        print("This browser edition binds only to 127.0.0.1. Keep this console open; press Ctrl+C to stop.")
        webbrowser.open(backend.url)
        try:
            while backend.process and backend.process.poll() is None:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\\nStopping VaultShield…")
    print("VaultShield stopped. Your encrypted demo vault is saved locally.")


if __name__ == "__main__":
    main()
