# VaultShield explained simply

Think of a record as a small document containing a website name, username, password, URL and notes. VaultShield locks that whole document **before** sending it to the server.

## Only three main parts

| Part | What it does |
|---|---|
| Desktop window | Lets you enter, encrypt, decrypt and search your dummy credentials |
| Local Python HTTPS server | Checks your login, ownership and update versions; stores encrypted data |
| SQLite database file | Saves accounts, encrypted records, encrypted vault key and metadata |

Both client and server run on your laptop for the demonstration. They are separate Python processes and communicate through verified HTTPS. Docker and a separate Nginx gateway are unnecessary for this learning setup.

## Why there are two passwords

**Account password:** proves to the server that you may access your account. It is sent over HTTPS, and the server stores a salted PBKDF2 verifier rather than the password.

**Master passphrase:** unlocks the vault key on your computer. It is never sent to the server. The account password is not used as the vault encryption key.

## What happens when you create a vault

1. Python's OS-backed randomness generates a 32-byte vault key.
2. PBKDF2-HMAC-SHA-256 turns the master passphrase plus a random 16-byte salt into a separate wrapping key. It uses 600,000 iterations.
3. AES-256-GCM encrypts the vault key with that wrapping key, a fresh 12-byte nonce and a 16-byte authentication tag.
4. The server stores this encrypted key envelope, never the plaintext vault key.

## What happens when you save and open a record

1. The desktop collects all five record fields together.
2. It encrypts them with AES-256-GCM under the vault key, using a fresh nonce.
3. Associated data binds the ciphertext to the account, vault, record ID, versions and revision.
4. HTTPS transports the ciphertext to the server. SQLite stores that ciphertext and non-sensitive routing/version metadata.
5. On reading, the desktop verifies the authentication tag and decrypts locally. A wrong key, modified ciphertext or substituted context is rejected.

The server can see account identifiers, record IDs, sizes, timestamps and access patterns. The stored title, username, password, URL and notes are encrypted.

## Two different layers of encryption

| Layer | Purpose |
|---|---|
| Client-side AES-256-GCM | Keeps stored vault content encrypted even after HTTPS ends |
| TLS 1.3 | Protects network traffic and authenticates the local server |

TLS uses the Python/OpenSSL implementation. P-256 ECDHE establishes a shared secret; certificate verification authenticates the server; HKDF derives traffic keys; the negotiated TLS cipher encrypts traffic. These are separate functions. The TLS traffic keys are different from the vault key.

The launcher makes a local CA and localhost certificate using the `cryptography` library. The client explicitly trusts that CA certificate and checks the hostname. It never switches verification off. The CA private key is not saved.

## What the buttons demonstrate

| Action | What happens |
|---|---|
| Lock | Clears the visible records and drops local key references |
| Unlock | Uses the master passphrase to recover the vault key locally |
| Change master passphrase | Rewraps the same vault key using a new salt, wrapping key and nonce |
| Change account password | Replaces the server login verifier and revokes account sessions; vault encryption is unchanged |
| Edit | Encrypts a new revision; stale versions receive a conflict |
| Log out | Asks the server to revoke the login token and clears local state |

Locking is not a promise of secure memory erasure. Changing the master passphrase does not make a stolen old envelope disappear. Revision checks handle stale updates, not full rollback by a malicious server.

## Where to look in the code

| File | Concept to explain in the review |
|---|---|
| `client/crypto.py` | AES-GCM, PBKDF2, nonces, tags, associated data |
| `client/service.py` | Unlock, lock, save, search preparation and rewrapping |
| `server/security.py` | Password verifier, token hashing and login throttling |
| `server/app.py` | Account endpoints, ownership and revision checks |
| `server/models.py` | Database fields, with no plaintext record fields |
| `scripts/local_demo.py` | Automatic local certificate and backend startup |
| `scripts/local_server.py` | Direct TLS 1.3 server configuration |
| `tests/` | Tampering, wrong-password, ownership, sessions, concurrency and restart evidence |

Course: **26ECSC403 — Cryptography and Network Security**. This is an educational use of established cryptography, not a novel algorithm or formal zero-knowledge proof.
