# VaultShield Web — Local Cryptography & Network Security Demo

VaultShield is now a browser-based application. The Python FastAPI backend and existing SQLite schema remain in place; the old Tkinter desktop client is no longer used by the default launcher.

## Run on Windows

1. Install Python 3.11, 3.12 or 3.13.
2. Extract this ZIP completely.
3. Open the `VaultShield_Simple` folder.
4. Double-click `Start_VaultShield.bat`, or run `py -3.11 run_demo.py` from PowerShell.
5. Your browser opens the local application. Keep the console window open; press Ctrl+C in it to stop the server.

The first run creates `.venv` without relying on `ensurepip`, then uses the installed Python pip to install the pinned, hash-checked dependencies. Internet is needed for first-time dependency installation.

## Browser application

- Separate account registration and login screens.
- Separate master-passphrase create/unlock screen.
- Credential vault with add, edit, search and delete.
- Browser-side PBKDF2-HMAC-SHA256 key derivation and AES-256-GCM encryption/decryption.
- Cyber Attack Simulation Lab with four selectable attack cards and detailed backend-generated walkthroughs.
- Authenticated server audit history.

## Cyber Attack Lab

Select one of four scenarios and click **Run selected simulation**:
- MITM — models attempted server impersonation and explains certificate/hostname validation and authenticated TLS.
- Replay — models reuse of an old operation and explains server-side session expiry/revocation and record revision checks.
- Brute force — uses synthetic failed-attempt events and explains PBKDF2 password verification and online rate limiting.
- Ciphertext tampering — models a ciphertext bit flip and explains AES-GCM authentication-tag rejection.

Each run calls the authenticated `POST /security/simulations` API. The backend creates an account-scoped `simulation.*` audit event and returns the scenario explanation, execution steps, defence details, result and simulation ID. The browser verifies that the response contains the expected evidence before displaying a completed report. These are deterministic educational simulations; they do not attack real networks, accounts or stored vault records.

## Important local transport limitation

The browser edition runs the API on `127.0.0.1` using HTTP so the browser can open it without asking you to install a local certificate authority. The server binds only to loopback and is intended for a single-computer academic demonstration. Do not expose this server to a LAN or the internet. For deployment beyond this local demo, put it behind properly configured HTTPS (TLS 1.3), secure cookies/token handling, CSRF protection, a production database and deployment hardening.

The legacy HTTPS/TLS self-test path remains available via `py -3.11 run_demo.py --self-test`. It tests the HTTPS API separately; it is not the transport used by the browser UI.

## Data location and backups

- `.demo-data/vaultshield.db` — accounts, encrypted records, key envelope and audit events.
- `.demo-data/` — local demo database and runtime data.
- `.venv/` — isolated Python dependencies.

Keep `.demo-data` private. Do not delete it if you need your existing encrypted vault. The master passphrase is not recoverable by the server. Use dummy credentials for academic demonstrations.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Read `HOW_IT_WORKS.md` and `docs/attack-lab.md` for implementation details and the CNS review explanation.


## Attack flow diagrams and backend execution

The Attack Lab flow diagrams are rendered from `execution_trace` values returned by the authenticated backend endpoint. A green/blocked node indicates the backend's observed result, not a frontend-only animation. The MITM test performs a real TLS handshake against a temporary untrusted loopback certificate; replay, brute-force throttling and AES-GCM tampering are executed in isolated backend test objects.

If the browser does not open automatically, copy the `http://127.0.0.1:<port>` address printed in PowerShell into Chrome. Keep the PowerShell window open while the server is running.


## Cyber Attack & Defence Lab (backend-executed)

All four lab scenarios execute bounded backend experiments against disposable local test objects:
- MITM: real TLS handshake against a temporary self-signed loopback server; trusted-certificate validation should reject it.
- Replay: HMAC-SHA256 authenticated dummy request accepted once and rejected when the same nonce/signature is replayed.
- Brute force: synthetic candidate passwords tested against a disposable PBKDF2-HMAC-SHA256 verifier and the actual backend RateLimiter.
- Ciphertext tampering: AES-256-GCM ciphertext is modified and normal authenticated decryption should raise InvalidTag.

The browser renders the backend's returned execution trace, backend event log and before/after defence comparison. Every run is authenticated and added to the server audit history. These are isolated educational tests, not attacks against real accounts, LAN devices or external services.
