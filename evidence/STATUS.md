# Simple edition — actual verification

Date: 8 November 2026. Environment: Linux, Python 3.12.14. Local simulated-cloud demonstration only.

## Executed successfully

- First-run `python run_demo.py --self-test` created a fresh virtual environment, installed the hashed runtime dependency lock, passed `pip check`, started direct Python HTTPS and completed the dummy-data workflow. See `launcher-first-run.txt`.
- Direct HTTPS self-test: create, unlock, edit, master-passphrase rewrap, delete, logout revocation and fresh-client re-unlock. All seven checks true. Actual observed protocol/cipher: TLSv1.3 / TLS_AES_256_GCM_SHA384 in this environment. See `simple-https-self-test.txt`.
- Complete suite: **63 passed, zero skipped**, one upstream Starlette test-transport deprecation warning; 15.13 seconds. See `test-output.txt` and `junit-simple.xml`.
- Included tests cover the original cryptographic/API protections plus certificate generation with no external executable, certificate reuse/non-overwrite, one-instance locking, the real direct-HTTPS process lifecycle, process restart recovery and automated GUI opening/closing on a virtual display.
- The CA/leaf certificate and server SSL context are created using Python libraries. No Docker, Nginx or standalone OpenSSL executable is used by the launcher. An optional extended OpenSSL transcript test was run where that executable was available; it is not needed to use the demo.

## Not executed / not claimed

- Windows `Start_VaultShield.bat` execution and Windows-specific file locking have not been run here. The launcher is provided for testing on the user's Windows laptop.
- This is not a remote cloud deployment or a production security audit.
- No RAM usage or “will never hang” guarantee is claimed. Containers and their virtualization layer are removed; the app runs two ordinary Python processes.
- No full manual user click-through or independent usability study is claimed. Existing GUI screens are retained and automated launch/timeout checks passed.

The earlier Nginx deployment is not part of this edition. The core client encryption, passphrase separation, ownership and stale-update controls remain. Cipher suites can vary with the installed Python/OpenSSL build; the interface shows the actual negotiated result.
