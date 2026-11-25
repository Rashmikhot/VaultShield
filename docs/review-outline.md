# Simple review presentation: 8 slides

1. **Problem and goal** — protect saved credentials during transmission and storage. Local demonstration of cloud-style synchronization.
2. **Three components** — Python desktop, local HTTPS server and SQLite. Show that client and server are separate processes; no Docker required.
3. **Two passwords** — account password authenticates; master passphrase unlocks locally.
4. **Encryption and keys** — random 256-bit vault key; PBKDF2 wrapping key; AES-256-GCM with fresh nonce and authentication tag.
5. **Secure transmission** — TLS 1.3, P-256 ECDHE, trusted local CA, hostname verification; show the actually observed TLS cipher.
6. **Live demonstration** — register, unlock, add/edit a dummy credential, mask/reveal, lock, change master passphrase and reopen.
7. **Attack tests** — wrong passphrase; tampered ciphertext; substituted record; another user's access; stale edits; restart. Use actual test results from this edition.
8. **Limitations and learning** — offline guesses, trusted client/OS, no recovery, no guaranteed memory erasure, no full rollback prevention. Explain how the implementation maps to AES, modes, passwords, key management, ECC/DH, TLS and cloud security.

Say during the review: “We use a local Python server as a simulated cloud. The deployment is simple, while the client still encrypts before upload and decrypts after retrieval.”

Do not describe this local setup as a remote cloud deployment. Do not claim the TLS cipher is fixed across every Python build; show what was negotiated. The standalone OpenSSL executable is optional for extended protocol evidence, not required to use the app.
