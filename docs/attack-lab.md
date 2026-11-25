# VaultShield Cyber Attack & Defence Laboratory

The authenticated browser UI calls `POST /security/simulations`. The Python backend executes bounded experiments against disposable lab objects, returns the ordered `execution_trace`, `execution_logs`, `before_after` comparison, evidence and simulation ID, then persists an account-scoped `simulation.<kind>` audit event. The UI builds its flowchart and event console from those returned backend fields. A run is only marked complete when the backend response includes execution evidence.

## Scenario execution

### 1. MITM / untrusted TLS certificate
The backend generates a short-lived self-signed certificate and private key, starts a temporary TLS server bound only to `127.0.0.1`, then connects with Python's normal trusted-CA and hostname-verification context. The handshake should fail with `SSLCertVerificationError` before application data is exchanged. This is a real local TLS certificate-validation experiment demonstrating a key MITM defence. It is not ARP spoofing, DNS poisoning, packet capture or interception of a third-party connection.

### 2. Replay
The backend constructs a dummy request with a random nonce and HMAC-SHA256 signature. It verifies and accepts the original request, records the nonce, then submits the exact same body, nonce and signature again. The signature remains valid, but the second request is rejected because the nonce was already consumed. The replay cache is isolated to that run; a production implementation should persist nonce state with expiry and bind it to authenticated user/session identity.

### 3. Brute force
The backend creates a disposable synthetic password verifier using PBKDF2-HMAC-SHA256 and a random salt. It submits a bounded list of dummy candidate passwords through the actual `RateLimiter` class. Only the allowed attempts perform PBKDF2 derivations; excess attempts are rejected before derivation. This does not target a real VaultShield account, use a real password list, or call the account login endpoint.

### 4. Ciphertext tampering
The backend creates a disposable AES-256-GCM key, nonce and dummy plaintext. It encrypts the data, flips one ciphertext bit while preserving the original authentication tag, then calls the normal AES-GCM decrypt operation. The expected `InvalidTag` exception demonstrates that modified ciphertext is rejected before plaintext is returned. No user's encrypted record or database row is modified.

## Scope and limitations

All experiments are bounded and use temporary in-memory objects or a temporary TLS server bound to loopback. They do not attack public IPs, LAN devices, third-party services, or real user accounts. The browser edition itself is a local HTTP application bound to `127.0.0.1`; do not expose it to a network. Any network deployment requires HTTPS with a trusted certificate, secure session handling, and deployment hardening.

The flowchart and event console are generated from backend-returned `execution_trace` and `execution_logs`, not from hard-coded frontend-only outcomes. Audit history records each authenticated simulation run.
