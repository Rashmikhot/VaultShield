"""First-run installer and launcher for VaultShield Web."""
import hashlib, os, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent

def main():
    os.chdir(ROOT)
    if not (3, 11) <= sys.version_info[:2] < (3, 14):
        raise RuntimeError("Install Python 3.11, 3.12 or 3.13.")
    virtual = ROOT / ".venv"
    python = virtual / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.exists():
        print("Creating isolated Python environment...", flush=True)
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(virtual)], check=True)
    requirement = ROOT / "requirements.txt"
    fingerprint = hashlib.sha256(requirement.read_bytes()).hexdigest()
    marker = virtual / "vaultshield-dependencies.sha256"
    if not marker.exists() or marker.read_text().strip() != fingerprint:
        print("Installing pinned backend libraries. Internet is required on first run.", flush=True)
        subprocess.run([sys.executable, "-m", "pip", "--python", str(python), "install",
                        "--disable-pip-version-check", "--require-hashes", "-r", str(requirement)], check=True)
        marker.write_text(fingerprint)
    print("Starting VaultShield Web...", flush=True)
    subprocess.run([str(python), "-m", "scripts.local_demo"], cwd=ROOT, check=True)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\\nStopped.")
    except Exception as e:
        print(f"\\nVaultShield could not start: {e}")
        print("See README.md for troubleshooting.")
        raise
