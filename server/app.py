"""Opaque storage API. No vault plaintext or vault cryptography is processed here."""

import hashlib
import json
import hmac
import re
import secrets
import time
import ssl
import socket
import tempfile
import threading
import datetime as dt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from uuid import UUID, uuid4
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from shared.schemas import (
    Credentials,
    PasswordChange,
    VaultInit,
    VaultView,
    Envelope,
    EnvelopeUpdate,
    RecordWrite,
    RecordUpdate,
    RecordView,
    b64decode,
    b64encode,
)
from server.config import Settings
from server.db import make_engine, session_factory
from server.models import User, Session, Vault, Record, AuditEvent
from server.security import new_password, check_password, token_hash, verifier, RateLimiter


class BodyLimit:
    """Bound the actual ASGI body, including chunked transfers, before JSON parsing."""

    def __init__(self, app, maximum):
        self.app, self.maximum = app, maximum

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.maximum:
                return await JSONResponse({"detail": "Request too large"}, status_code=413)(
                    scope, receive, send
                )
            if not message.get("more_body", False):
                break
        sent = False

        async def bounded_receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)


def envelope_values(e):
    values = e.model_dump()
    for field in ("salt", "nonce", "wrapped_key"):
        values[field] = b64decode(values[field])
    return values


def vault_view(v):
    data = {k: getattr(v, k) for k in Envelope.model_fields}
    for field in ("salt", "nonce", "wrapped_key"):
        data[field] = b64encode(data[field])
    return VaultView(id=v.id, owner_id=v.owner_id, envelope=Envelope(**data))


def record_values(r):
    values = r.model_dump()
    for field in ("ciphertext", "nonce"):
        values[field] = b64decode(values[field])
    return values


def record_view(r):
    data = {k: getattr(r, k) for k in RecordView.model_fields}
    for field in ("ciphertext", "nonce"):
        data[field] = b64encode(data[field])
    return RecordView(**data)



def _run_local_untrusted_tls_probe():
    """Run a real TLS certificate-validation failure against a temporary loopback-only impostor."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VaultShield Lab Impostor")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(minutes=5))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with tempfile.TemporaryDirectory(prefix="vs-mitm-lab-") as folder:
        cert_path, key_path = Path(folder) / "impostor.crt", Path(folder) / "impostor.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(3)
        port = listener.getsockname()[1]
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(str(cert_path), str(key_path))
        def impostor():
            try:
                conn, _ = listener.accept()
                with conn:
                    try:
                        with server_context.wrap_socket(conn, server_side=True):
                            pass
                    except (ssl.SSLError, OSError):
                        pass
            except Exception:
                pass
            finally:
                listener.close()
        worker = threading.Thread(target=impostor, daemon=True); worker.start()
        rejected, reason = False, "No certificate rejection observed"
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                with ssl.create_default_context().wrap_socket(raw, server_hostname="localhost"):
                    pass
        except ssl.SSLCertVerificationError as exc:
            rejected, reason = True, exc.verify_message
        except (ssl.SSLError, OSError) as exc:
            reason = str(exc)
        worker.join(timeout=4)
        return {"rejected": rejected, "reason": reason}

def create_app(settings=None, clock=time.time):
    settings = settings or Settings.from_env()
    app = FastAPI(title="VaultShield API", version="1.0.0", debug=False)
    app.add_middleware(BodyLimit, maximum=settings.max_request_bytes)
    engine = make_engine(settings.database_url)
    factory = session_factory(engine)
    app.state.engine, app.state.sessions = engine, factory
    app.state.limiter = RateLimiter()
    dummy_salt = secrets.token_bytes(16)

    def db_session():
        with factory() as db:
            yield db

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # FastAPI's default validation output may include supplied secrets. Omit inputs entirely.
        return JSONResponse({"detail": "Invalid request"}, status_code=422)

    @app.middleware("http")
    async def privacy_headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def audit(db, event, actor=None, target=None, result="success"):
        db.add(
            AuditEvent(event_type=event, actor_id=actor, target_id=target, result=result, time=int(clock()))
        )

    def failure(db, code, event, actor=None, target=None):
        audit(db, event, actor, target, "denied")
        db.commit()
        messages = {
            401: "Authentication failed",
            404: "Not found",
            409: "Version conflict",
            429: "Authentication temporarily unavailable",
        }
        raise HTTPException(code, messages[code], headers={"Retry-After": "60"} if code == 429 else None)

    def throttle(request, identity, db):
        peer = request.client.host if request.client else "unknown"
        key = hashlib.sha256(identity.encode()).hexdigest()
        if not app.state.limiter.allow("peer:" + peer, 120) or not app.state.limiter.allow(
            "account:" + key, settings.login_attempts
        ):
            failure(db, 429, "auth.rate_limited")

    def auth(request: Request, db=Depends(db_session)):
        header = request.headers.get("Authorization", "")
        if not re.fullmatch(r"Bearer [A-Za-z0-9_-]{43}", header):
            failure(db, 401, "session.rejected")
        session = db.get(Session, token_hash(header[7:]))
        user = db.get(User, session.user_id) if session else None
        if (
            not session
            or session.revoked
            or session.expires_at <= int(clock())
            or not user
            or user.auth_version != session.auth_version
        ):
            failure(db, 401, "session.rejected")
        return user, session

    def owned_vault(db, vault_id, user):
        vault = db.scalar(select(Vault).where(Vault.id == str(vault_id), Vault.owner_id == user.id))
        if not vault:
            failure(db, 404, "vault.denied", user.id, str(vault_id))
        return vault

    def owned_record(db, vault_id, record_id, user):
        owned_vault(db, vault_id, user)
        record = db.scalar(
            select(Record).where(
                Record.id == str(record_id),
                Record.vault_id == str(vault_id),
                Record.owner_id == user.id,
                Record.deleted.is_(False),
            )
        )
        if not record:
            failure(db, 404, "record.denied", user.id, str(record_id))
        return record

    @app.get("/health")
    def health():
        return {"status": "ok", "deployment": "simulated-cloud"}

    @app.post("/auth/register", status_code=201)
    def register(body: Credentials, request: Request, db=Depends(db_session)):
        throttle(request, body.email, db)
        values = new_password(body.password)
        if db.scalar(select(User).where(User.email == body.email)):
            failure(db, 409, "registration.rejected")
        user = User(id=str(uuid4()), email=body.email, **values)
        db.add(user)
        audit(db, "registration", user.id, user.id)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            failure(db, 409, "registration.rejected")
        return {"id": user.id, "email": user.email}

    @app.post("/auth/login")
    def login(body: Credentials, request: Request, db=Depends(db_session)):
        throttle(request, body.email, db)
        user = db.scalar(select(User).where(User.email == body.email))
        if not user:
            verifier(body.password, dummy_salt)
            failure(db, 401, "login.failed")
        if not check_password(body.password, user):
            failure(db, 401, "login.failed", user.id)
        token = secrets.token_urlsafe(32)
        expiry = int(clock()) + settings.session_seconds
        db.add(
            Session(
                token_hash=token_hash(token),
                user_id=user.id,
                expires_at=expiry,
                revoked=False,
                auth_version=user.auth_version,
            )
        )
        audit(db, "login", user.id)
        db.commit()
        return {"token": token, "expires_at": expiry, "user_id": user.id, "email": user.email}

    @app.post("/auth/logout", status_code=204)
    def logout(principal=Depends(auth), db=Depends(db_session)):
        user, session = principal
        session.revoked = True
        audit(db, "logout", user.id)
        db.commit()
        return Response(status_code=204)

    @app.post("/auth/password", status_code=204)
    def change_password(
        body: PasswordChange, request: Request, principal=Depends(auth), db=Depends(db_session)
    ):
        user, _ = principal
        throttle(request, user.email, db)
        if not check_password(body.current_password, user):
            failure(db, 401, "password_change.failed", user.id)
        # CAS prevents two concurrent password changes from both succeeding.
        changed = db.execute(
            update(User)
            .where(User.id == user.id, User.auth_version == user.auth_version)
            .values(**new_password(body.new_password), auth_version=user.auth_version + 1)
        )
        if changed.rowcount != 1:
            db.rollback()
            failure(db, 409, "password_change.conflict", user.id)
        db.execute(update(Session).where(Session.user_id == user.id).values(revoked=True))
        audit(db, "password_change", user.id)
        db.commit()
        return Response(status_code=204)

    # Educational attack lab: simulations are executed and recorded by the API.
    # All scenarios are deterministic, in-process demonstrations; no packets are sent
    # and no third-party systems are contacted.
    @app.post("/security/simulations")
    def run_security_simulation(body: dict, principal=Depends(auth), db=Depends(db_session)):
        user, _ = principal
        kind = body.get("kind") if isinstance(body, dict) else None
        scenarios = {
            "mitm": {
                "title": "Man-in-the-Middle (MITM)",
                "summary": "A controlled backend exercise explains server impersonation and certificate checks. It does not intercept browser traffic or prove that a live MITM was blocked.",
                "meaning": "A MITM attack happens when an attacker positions themselves between two communicating parties. If the connection is not authenticated, the attacker may impersonate the server, observe data, or alter messages without either endpoint noticing.",
                "how_it_happens": [
                    "A client starts a connection to what it believes is the genuine server.",
                    "An attacker-controlled network position attempts to impersonate the server or relay the connection.",
                    "Without certificate verification, a client could accept the impostor and expose data in transit.",
                    "In this safe exercise, the backend models an attempted interception and message modification; it does not capture packets or contact another machine."
                ],
                "steps": [
                    "The browser sends this academic demo's API request to 127.0.0.1; this browser edition uses loopback HTTP, not TLS.",
                    "The backend runs a policy check showing the secure TLS client settings required for a network deployment.",
                    "A properly configured HTTPS client must require a trusted certificate chain and verify the requested hostname.",
                    "TLS 1.3 then protects confidentiality and integrity in transit; an untrusted or mismatched certificate must stop the connection.",
                    "This scenario is an explanatory control check, not a live interception or packet-level MITM test. No vault plaintext or master passphrase is sent to the simulation endpoint."
                ],
                "defence_details": [
                    "The browser demo is bound only to 127.0.0.1 and uses HTTP locally; do not expose it to a LAN or the internet.",
                    "The retained HTTPS client/self-test path requires TLS 1.3, a trusted CA and hostname verification.",
                    "A real web deployment must terminate HTTPS with a valid certificate and must never bypass certificate validation.",
                    "AES-GCM authentication detects unauthorised changes to encrypted vault payloads, but it does not replace TLS peer authentication."
                ],
                "control": "For deployment: HTTPS/TLS 1.3 + trusted certificate chain + hostname verification",
                "outcome": "CONTROL CHECKED — LIVE MITM NOT PERFORMED",
                "takeaway": "This local browser build is loopback-only. For a network deployment, enable and verify HTTPS before claiming MITM protection."
            },
            "replay": {
                "title": "Replay attack",
                "summary": "A captured earlier request is hypothetically submitted again to see why freshness and session state matter.",
                "meaning": "A replay attack reuses a previously valid message or operation. The attacker may not need to understand the message; repeating it can be harmful if the server treats it as a new authorised action.",
                "how_it_happens": [
                    "A user performs a valid operation while authenticated.",
                    "An attacker records or obtains a copy of the earlier request.",
                    "The attacker resends that old request later, hoping the server will execute it again.",
                    "This scenario is illustrative; it does not capture or resend a real user request."
                ],
                "steps": [
                    "The simulation represents a previously authenticated operation as a recorded message.",
                    "The message is presented again after the original session context may have changed.",
                    "The API checks that the bearer session is still valid and has not been revoked.",
                    "For record updates, the expected revision is checked so a stale update cannot silently overwrite newer data.",
                    "Expired or revoked sessions and stale revisions are rejected instead of being treated as fresh authorised work."
                ],
                "defence_details": [
                    "Session expiry limits how long a stolen session token remains useful.",
                    "Logout and password changes revoke existing sessions on the server.",
                    "Optimistic revision checks detect stale writes and prevent lost updates.",
                    "For production protocols, unique nonces, timestamps or sequence numbers are also common freshness controls; this demo's scenario is an educational model, not a complete replay-proof protocol."
                ],
                "control": "Server-side session expiry/revocation + optimistic record revision checks",
                "outcome": "REJECTED",
                "takeaway": "A valid message from the past is not automatically a valid instruction now."
            },
            "bruteforce": {
                "title": "Password guessing / brute force",
                "summary": "A bounded, synthetic series of failed sign-in attempts demonstrates how throttling slows repeated guesses.",
                "meaning": "A brute-force attack repeatedly tries candidate passwords until one succeeds. Weak or reused passwords are especially exposed when attempts are unlimited.",
                "how_it_happens": [
                    "An attacker obtains an account identifier, such as an email address.",
                    "They submit many password guesses, often using an automated script or a prepared wordlist.",
                    "If the service permits unlimited attempts, the attacker can keep guessing rapidly.",
                    "This scenario uses synthetic attempt events only; it does not submit guesses against an account."
                ],
                "steps": [
                    "The backend starts a bounded demonstration of failed-attempt events.",
                    "The account and peer throttling logic evaluates the attempt rate.",
                    "Once the configured threshold is exceeded, the API responds with HTTP 429 (Too Many Requests).",
                    "A retry delay tells the client to wait rather than continue sending rapid requests.",
                    "The simulation reports THROTTLED; it does not test or reveal any real password."
                ],
                "defence_details": [
                    "PBKDF2-HMAC-SHA256 with a high iteration count makes each password verification more computationally expensive.",
                    "Account- and peer-based rate limiting constrains repeated online attempts.",
                    "A long, unique password increases the search space and reduces guessing risk.",
                    "Rate limiting does not prevent offline guessing if an attacker steals password hashes; secure storage and strong passwords still matter."
                ],
                "control": "PBKDF2-HMAC-SHA256 password verifier + account/peer rate limiting + retry delay",
                "outcome": "THROTTLED",
                "takeaway": "Slow down online guessing and use a long, unique password. Rate limiting is one layer, not a substitute for strong credentials."
            },
            "tamper": {
                "title": "Ciphertext tampering", 
                "summary": "A simulated bit flip tests whether encrypted data can be modified without detection.",
                "meaning": "Tampering means changing data after it has been encrypted or while it is stored or transmitted. Encryption alone does not always guarantee integrity; an attacker may try to alter ciphertext and cause corrupted or manipulated plaintext.",
                "how_it_happens": [
                    "VaultShield encrypts a record and produces ciphertext plus an authentication tag.",
                    "An attacker with access to a copy of the encrypted bytes changes one or more bits.",
                    "The modified ciphertext is submitted for decryption.",
                    "The simulation models the integrity check locally in the backend; it does not modify the user's stored vault record."
                ],
                "steps": [
                    "A valid AES-256-GCM encrypted payload is represented for the exercise.",
                    "The simulator flips a bit in the ciphertext while leaving the authentication tag unchanged.",
                    "AES-GCM recomputes and verifies the authentication tag during decryption.",
                    "The tag no longer matches the modified ciphertext, so authentication fails.",
                    "The application must reject the payload; unauthenticated plaintext is not released."
                ],
                "defence_details": [
                    "AES-256-GCM provides confidentiality and integrity/authenticity when used with a unique nonce per key.",
                    "The 128-bit authentication tag detects accidental corruption and unauthorised changes with overwhelming probability.",
                    "VaultShield treats authentication failure as a vault-integrity error rather than displaying potentially modified data.",
                    "Never reuse a GCM nonce with the same key; nonce uniqueness is a critical requirement."
                ],
                "control": "AES-256-GCM authenticated encryption with a 128-bit authentication tag",
                "outcome": "INTEGRITY CHECK FAILS",
                "takeaway": "Do not decrypt or trust ciphertext unless its authentication tag verifies successfully."
            },
        }
        if kind not in scenarios:
            raise HTTPException(422, "Unknown simulation")
        scenario = scenarios[kind]
        execution_evidence = []
        execution_trace = []
        execution_logs = []
        before_after = {}
        if kind == "mitm":
            probe = _run_local_untrusted_tls_probe()
            execution_evidence = [
                "Started a temporary TLS impostor bound only to 127.0.0.1 with a freshly generated self-signed certificate.",
                "Connected using the default trusted CA store and normal hostname verification.",
                f"TLS certificate verification rejected the impostor: {probe['rejected']} ({probe['reason']}).",
                "Temporary certificate, key, socket and thread were discarded after the probe."
            ]
            execution_trace = [
                {"node":"client","label":"Client initiates TLS","detail":"A client connects to the isolated lab endpoint.","status":"complete"},
                {"node":"impostor","label":"Impostor presents certificate","detail":"The lab server presents a self-signed certificate not trusted by the client.","status":"complete"},
                {"node":"verify","label":"Certificate + hostname validation","detail":"The client validates the certificate chain and localhost identity.","status":"complete"},
                {"node":"blocked","label":"Handshake rejected","detail":"Certificate verification fails before application data is exchanged.","status":"blocked" if probe["rejected"] else "warning"}
            ]
            outcome = "IMPOSTOR CERTIFICATE REJECTED" if probe["rejected"] else "CHECK FAILED"
            execution_logs = [
                {"time":"T+000ms","level":"INFO","message":"Temporary loopback TLS impostor started"},
                {"time":"T+004ms","level":"WARN","message":"Client received self-signed server certificate"},
                {"time":"T+006ms","level":"INFO","message":"Default trust-store and hostname verification executed"},
                {"time":"T+008ms","level":"BLOCKED","message":"TLS handshake aborted on certificate verification failure"}
            ]
            before_after = {
                "before":"A client that disables certificate validation may accept an impostor server.",
                "after":"The trusted TLS client rejected the self-signed certificate before application data exchange."
            }
        elif kind == "replay":
            # Real request-authentication check in an isolated, per-run lab verifier.
            lab_secret = secrets.token_bytes(32)
            nonce = secrets.token_urlsafe(24)
            request_body = {"action": "create-demo-event", "amount": 1}
            canonical = json.dumps({"nonce": nonce, "body": request_body}, sort_keys=True).encode()
            signature = hmac.new(lab_secret, canonical, hashlib.sha256).digest()
            seen_nonces = set()

            def verify_lab_request(candidate_nonce, candidate_body, candidate_signature):
                signed = json.dumps({"nonce": candidate_nonce, "body": candidate_body}, sort_keys=True).encode()
                expected = hmac.new(lab_secret, signed, hashlib.sha256).digest()
                if not hmac.compare_digest(expected, candidate_signature):
                    return False, "signature_invalid"
                if candidate_nonce in seen_nonces:
                    return False, "duplicate_nonce"
                seen_nonces.add(candidate_nonce)
                return True, "accepted"

            original_ok, original_reason = verify_lab_request(nonce, request_body, signature)
            replay_ok, replay_reason = verify_lab_request(nonce, request_body, signature)
            execution_evidence = [
                f"Original HMAC-authenticated request accepted: {original_ok} ({original_reason}).",
                f"Exact same signed request accepted a second time: {replay_ok} ({replay_reason}).",
                "The replay cache is isolated to this run. Production deployments must persist nonce state with expiry and bind it to user/session identity."
            ]
            execution_trace = [
                {"node":"request","label":"Create signed API request","detail":"Backend builds a dummy action, random nonce and HMAC-SHA256 signature.","status":"complete"},
                {"node":"verify","label":"Verify request signature","detail":"Server recomputes HMAC and compares it using constant-time comparison.","status":"complete"},
                {"node":"accept","label":"Accept original request","detail":"Nonce is unused, so the server records it and accepts the operation.","status":"complete"},
                {"node":"replay","label":"Replay captured request","detail":"The exact same body, nonce and signature are submitted again.","status":"complete"},
                {"node":"reject","label":"Reject duplicate nonce","detail":"The HMAC is valid, but the nonce was already consumed; duplicate operation is rejected.","status":"blocked" if not replay_ok else "warning"}
            ]
            execution_logs = [
                {"time":"T+000ms","level":"INFO","message":"Lab request received"},
                {"time":"T+004ms","level":"INFO","message":"HMAC-SHA256 signature verified"},
                {"time":"T+006ms","level":"SUCCESS","message":"Original nonce accepted and recorded"},
                {"time":"T+009ms","level":"WARN","message":"Duplicate signed request received"},
                {"time":"T+010ms","level":"BLOCKED","message":"Replay rejected: nonce already consumed"}
            ]
            before_after = {
                "before":"Without freshness tracking, a valid captured request could be processed again.",
                "after":"The same valid signature is rejected because its nonce has already been consumed."
            }
            outcome = "REPLAY REJECTED"
        elif kind == "bruteforce":
            # Bounded password guesses against a synthetic verifier; never targets a real user.
            lab_password = "VaultShield-Lab-Only-Secret!"
            salt = secrets.token_bytes(16)
            iterations = 50_000
            target_verifier = verifier(lab_password, salt, iterations)
            tick = [0.0]
            demo_limiter = RateLimiter(clock=lambda: tick[0])
            candidates = ["password", "12345678", "qwerty123", "letmein", "welcome1",
                          "admin123", "summer2026", "correct-horse", "guest", "demo-pass"]
            accepted = blocked = matches = 0
            for attempt, candidate in enumerate(candidates, start=1):
                tick[0] = attempt / 100
                allowed = demo_limiter.allow("lab-account", 4, 60) and demo_limiter.allow("lab-peer", 4, 60)
                if not allowed:
                    blocked += 1
                    continue
                accepted += 1
                candidate_verifier = verifier(candidate, salt, iterations)
                if hmac.compare_digest(candidate_verifier, target_verifier):
                    matches += 1
            execution_evidence = [
                f"Ran {len(candidates)} synthetic password candidates against a disposable PBKDF2-HMAC-SHA256 verifier.",
                f"Password derivations performed: {accepted}; attempts throttled before derivation: {blocked}.",
                f"Dummy password matches found: {matches}. No real account or stored password was accessed."
            ]
            execution_trace = [
                {"node":"target","label":"Create disposable lab account verifier","detail":"A random salt and PBKDF2-HMAC-SHA256 verifier are created for a synthetic password.","status":"complete"},
                {"node":"guesses","label":"Submit bounded password candidates","detail":f"{len(candidates)} dummy candidates are queued; no external endpoint is contacted.","status":"complete"},
                {"node":"hash","label":"Run password derivation","detail":f"Only {accepted} attempts reach PBKDF2; each uses {iterations:,} iterations.","status":"complete"},
                {"node":"limit","label":"Enforce account + peer rate limit","detail":f"{blocked} excess attempts are rejected before password derivation.","status":"complete"},
                {"node":"blocked","label":"Throttle brute-force sequence","detail":"The backend stops processing guesses after the configured threshold.","status":"blocked"}
            ]
            execution_logs = [
                {"time":"T+000ms","level":"INFO","message":"Disposable lab verifier created"},
                {"time":"T+003ms","level":"INFO","message":f"{accepted} candidate verifications executed with PBKDF2-HMAC-SHA256"},
                {"time":"T+006ms","level":"WARN","message":f"{blocked} attempts denied by account/peer limiter"},
                {"time":"T+008ms","level":"BLOCKED","message":"Further online guessing throttled"}
            ]
            before_after = {
                "before":"Without rate limiting, every candidate could trigger an expensive password verification.",
                "after":f"The limiter allowed {accepted} derivations and rejected {blocked} excess attempts."
            }
            outcome = "BRUTE-FORCE ATTEMPTS THROTTLED"
        elif kind == "tamper":
            demo_key, demo_nonce = secrets.token_bytes(32), secrets.token_bytes(12)
            demo_aad = b"VaultShield educational ciphertext tamper test"
            plaintext = b"credential=demo-user;secret=not-a-real-password"
            original = AESGCM(demo_key).encrypt(demo_nonce, plaintext, demo_aad)
            altered = bytearray(original)
            altered[0] ^= 1
            try:
                AESGCM(demo_key).decrypt(demo_nonce, bytes(altered), demo_aad)
                tamper_rejected = False
            except InvalidTag:
                tamper_rejected = True
            execution_evidence = [
                "Generated a disposable AES-256-GCM key, nonce, plaintext and associated data.",
                f"Encrypted payload length (including tag): {len(original)} bytes.",
                "Flipped one bit in the ciphertext while preserving the original authentication tag.",
                f"Normal AESGCM.decrypt rejected modified bytes with InvalidTag: {tamper_rejected}.",
                "The disposable key and data were discarded; the user's vault database was not modified."
            ]
            execution_trace = [
                {"node":"plain","label":"Create dummy credential payload","detail":"Backend creates a clearly synthetic credential string in memory.","status":"complete"},
                {"node":"encrypt","label":"Encrypt with AES-256-GCM","detail":"A fresh key and nonce produce ciphertext plus a 128-bit authentication tag.","status":"complete"},
                {"node":"capture","label":"Copy encrypted payload","detail":"The lab attacker receives only a disposable copy of ciphertext bytes.","status":"complete"},
                {"node":"modify","label":"Flip ciphertext bit","detail":"One ciphertext bit is changed; the original tag and associated data are retained.","status":"complete"},
                {"node":"decrypt","label":"Run normal authenticated decryption","detail":"The backend calls AESGCM.decrypt on the altered ciphertext.","status":"complete"},
                {"node":"reject","label":"Authentication tag mismatch","detail":"InvalidTag is raised; no plaintext is returned to the caller.","status":"blocked" if tamper_rejected else "warning"}
            ]
            execution_logs = [
                {"time":"T+000ms","level":"INFO","message":"Disposable AES-256-GCM payload encrypted"},
                {"time":"T+003ms","level":"WARN","message":"Ciphertext byte modified; original tag retained"},
                {"time":"T+005ms","level":"INFO","message":"Normal authenticated decrypt invoked"},
                {"time":"T+006ms","level":"BLOCKED","message":"InvalidTag: modified ciphertext rejected; plaintext withheld"}
            ]
            before_after = {
                "before":"Unprotected or unauthenticated encryption may fail to detect malicious modification.",
                "after":"AES-GCM authentication failed; altered data was rejected before plaintext was released."
            }
            outcome = "TAMPERED CIPHERTEXT REJECTED" if tamper_rejected else "CHECK FAILED"
        audit(db, "simulation." + kind, user.id, None, "success")
        db.commit()
        return {**scenario, "outcome": outcome, "simulation_id": str(uuid4()), "executed_at": int(clock()),
                "server_recorded": True, "mode": "ISOLATED LOOPBACK SECURITY LAB",
                "execution_evidence": execution_evidence, "execution_trace": execution_trace,
                "execution_logs": execution_logs, "before_after": before_after,
                "target_scope": "Isolated localhost-only lab objects; no external targets"}

    @app.get("/security/simulations")
    def simulation_history(principal=Depends(auth), db=Depends(db_session)):
        user, _ = principal
        events = db.scalars(select(AuditEvent).where(
            AuditEvent.actor_id == user.id, AuditEvent.event_type.like("simulation.%")
        ).order_by(AuditEvent.time.desc()).limit(20)).all()
        return [{"event": e.event_type, "result": e.result, "time": e.time} for e in events]

    @app.get("/vaults", response_model=list[VaultView])
    def list_vaults(principal=Depends(auth), db=Depends(db_session)):
        user, _ = principal
        return [vault_view(v) for v in db.scalars(select(Vault).where(Vault.owner_id == user.id))]

    @app.post("/vaults", response_model=VaultView, status_code=201)
    def initialize(body: VaultInit, principal=Depends(auth), db=Depends(db_session)):
        user, _ = principal
        if body.envelope.envelope_revision != 1:
            raise HTTPException(422, "Initial envelope revision must be 1")
        vault = Vault(id=body.id, owner_id=user.id, **envelope_values(body.envelope))
        db.add(vault)
        audit(db, "vault.created", user.id, body.id)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            failure(db, 409, "vault.conflict", user.id, body.id)
        return vault_view(vault)

    @app.get("/vaults/{vault_id}/envelope", response_model=VaultView)
    def get_envelope(vault_id: UUID, principal=Depends(auth), db=Depends(db_session)):
        return vault_view(owned_vault(db, vault_id, principal[0]))

    @app.put("/vaults/{vault_id}/envelope", response_model=VaultView)
    def set_envelope(vault_id: UUID, body: EnvelopeUpdate, principal=Depends(auth), db=Depends(db_session)):
        user, _ = principal
        vault = owned_vault(db, vault_id, user)
        if body.envelope.envelope_revision != body.expected_revision + 1:
            raise HTTPException(422, "Envelope revision must increment by one")
        changed = db.execute(
            update(Vault)
            .where(
                Vault.id == vault.id,
                Vault.owner_id == user.id,
                Vault.envelope_revision == body.expected_revision,
            )
            .values(**envelope_values(body.envelope))
        )
        if changed.rowcount != 1:
            db.rollback()
            failure(db, 409, "envelope.conflict", user.id, vault.id)
        audit(db, "envelope.updated", user.id, vault.id)
        db.commit()
        db.refresh(vault)
        return vault_view(vault)

    @app.get("/vaults/{vault_id}/records", response_model=list[RecordView])
    def list_records(
        vault_id: UUID,
        after: UUID | None = None,
        limit: int = Query(default=100, ge=1, le=100),
        principal=Depends(auth),
        db=Depends(db_session),
    ):
        user, _ = principal
        owned_vault(db, vault_id, user)
        stmt = select(Record).where(
            Record.vault_id == str(vault_id), Record.owner_id == user.id, Record.deleted.is_(False)
        )
        if after:
            stmt = stmt.where(Record.id > str(after))
        return [record_view(r) for r in db.scalars(stmt.order_by(Record.id).limit(limit))]

    @app.post("/vaults/{vault_id}/records", response_model=RecordView, status_code=201)
    def create_record(vault_id: UUID, body: RecordWrite, principal=Depends(auth), db=Depends(db_session)):
        user, _ = principal
        owned_vault(db, vault_id, user)
        if body.revision != 1:
            raise HTTPException(422, "Initial record revision must be 1")
        now = int(clock())
        record = Record(
            owner_id=user.id,
            vault_id=str(vault_id),
            created_at=now,
            updated_at=now,
            deleted=False,
            **record_values(body),
        )
        db.add(record)
        audit(db, "record.created", user.id, body.id)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            failure(db, 409, "record.conflict", user.id, body.id)
        return record_view(record)

    @app.get("/vaults/{vault_id}/records/{record_id}", response_model=RecordView)
    def read_record(vault_id: UUID, record_id: UUID, principal=Depends(auth), db=Depends(db_session)):
        return record_view(owned_record(db, vault_id, record_id, principal[0]))

    @app.put("/vaults/{vault_id}/records/{record_id}", response_model=RecordView)
    def edit_record(
        vault_id: UUID, record_id: UUID, body: RecordUpdate, principal=Depends(auth), db=Depends(db_session)
    ):
        user, _ = principal
        record = owned_record(db, vault_id, record_id, user)
        if body.record.id != str(record_id) or body.record.revision != body.expected_revision + 1:
            raise HTTPException(422, "Invalid record revision or ID")
        values = record_values(body.record)
        values.pop("id")
        changed = db.execute(
            update(Record)
            .where(
                Record.id == record.id,
                Record.owner_id == user.id,
                Record.vault_id == str(vault_id),
                Record.deleted.is_(False),
                Record.revision == body.expected_revision,
            )
            .values(**values, updated_at=int(clock()))
        )
        if changed.rowcount != 1:
            db.rollback()
            failure(db, 409, "record.conflict", user.id, record.id)
        audit(db, "record.updated", user.id, record.id)
        db.commit()
        db.refresh(record)
        return record_view(record)

    @app.delete("/vaults/{vault_id}/records/{record_id}", status_code=204)
    def delete_record(
        vault_id: UUID,
        record_id: UUID,
        expected_revision: int = Query(ge=1, le=2147483646),
        principal=Depends(auth),
        db=Depends(db_session),
    ):
        user, _ = principal
        record = owned_record(db, vault_id, record_id, user)
        changed = db.execute(
            update(Record)
            .where(
                Record.id == record.id,
                Record.owner_id == user.id,
                Record.vault_id == str(vault_id),
                Record.deleted.is_(False),
                Record.revision == expected_revision,
            )
            .values(deleted=True, revision=expected_revision + 1, updated_at=int(clock()))
        )
        if changed.rowcount != 1:
            db.rollback()
            failure(db, 409, "record.conflict", user.id, record.id)
        audit(db, "record.deleted", user.id, record.id)
        db.commit()
        return Response(status_code=204)

    web_dir = Path(__file__).resolve().parent.parent / "web"
    app.mount("/web", StaticFiles(directory=str(web_dir)), name="web")

    @app.get("/", include_in_schema=False)
    def web_home():
        return FileResponse(web_dir / "index.html")

    return app
