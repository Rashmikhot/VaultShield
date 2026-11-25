import datetime as dt
import shutil
import ssl
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from client.api import VaultAPI, APIError, tls_context
from scripts.local_demo import create_certificates as create
from scripts.tls_probe import probe


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    root = tmp_path_factory.mktemp("tls")
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VaultShield Test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .sign(ca_key, hashes.SHA256())
    )
    (root / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    key = ec.generate_private_key(ec.SECP256R1())
    (root / "server.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    for name, expired in [("server", False), ("expired", True)]:
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=3))
            .not_valid_after(now - dt.timedelta(days=1) if expired else now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(ca_key, hashes.SHA256())
        )
        (root / f"{name}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return root


@contextmanager
def https_server(root, name="server", tls12=False):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2 if tls12 else ssl.TLSVersion.TLSv1_3
    context.maximum_version = context.minimum_version
    context.load_cert_chain(root / f"{name}.crt", root / "server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.integration
def test_trusted_tls_and_actual_metadata(certs):
    with https_server(certs) as port:
        api = VaultAPI(f"https://localhost:{port}", str(certs / "ca.crt"))
        try:
            assert api.request("GET", "/health")["status"] == "ok"
            assert api.tls_info["protocol"] == "TLSv1.3"
            assert api.tls_info["cipher"].startswith("TLS_")
        finally:
            api.close()


@pytest.mark.integration
@pytest.mark.parametrize("failure", ["untrusted", "hostname", "expired", "tls12"])
def test_certificate_hostname_expiry_and_protocol_rejection(certs, failure):
    with https_server(certs, "expired" if failure == "expired" else "server", failure == "tls12") as port:
        host = "127.0.0.1" if failure == "hostname" else "localhost"
        ca = None if failure == "untrusted" else str(certs / "ca.crt")
        api = VaultAPI(f"https://{host}:{port}", ca)
        try:
            with pytest.raises(APIError, match="Secure connection failed"):
                api.request("GET", "/health")
        finally:
            api.close()


def test_verification_cannot_be_disabled_and_no_keylogging(certs, monkeypatch, tmp_path):
    log = tmp_path / "tls-keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(log))
    ctx = tls_context(str(certs / "ca.crt"))
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.keylog_filename is None


@pytest.mark.integration
def test_openssl_generator_and_negotiation_probe(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("OpenSSL executable is not available")
    root = tmp_path / "certs"
    create(root)
    with pytest.raises(FileExistsError, match="overwrite"):
        create(root)
    # Python server negotiates with a client restricted to the required suite/group.
    with https_server(root) as port:
        result = probe("localhost", port, root / "ca.crt")
        assert all(result["checks"].values()), result["transcript"]
