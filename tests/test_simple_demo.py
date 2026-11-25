import json
import ssl
import pytest
from client.api import VaultAPI, APIError
from client.service import VaultService
from shared.schemas import PlainRecord
from scripts.local_demo import LocalBackend, create_certificates, ensure_certificates, InstanceLock
from scripts.local_server import server_context


def test_certificate_setup_needs_no_external_executable(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "")
    certs = tmp_path / "certs"
    create_certificates(certs)
    before = {p.name: p.read_bytes() for p in certs.iterdir()}
    assert set(before) == {"ca.crt", "server.crt", "server.key"}
    assert not (certs / "ca.key").exists()
    ensure_certificates(certs)
    assert before == {p.name: p.read_bytes() for p in certs.iterdir()}
    with pytest.raises(FileExistsError):
        create_certificates(certs)
    context = server_context(certs)
    assert context.minimum_version == context.maximum_version == ssl.TLSVersion.TLSv1_3
    assert context.num_tickets == 0
    assert context.keylog_filename is None


def test_existing_partial_certificates_fail_without_overwriting(tmp_path):
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "ca.crt").write_text("partial-demo-file")
    with pytest.raises(RuntimeError, match="Incomplete"):
        ensure_certificates(certs)
    assert (certs / "ca.crt").read_text() == "partial-demo-file"


def test_single_instance_guard(tmp_path):
    first, second = InstanceLock(tmp_path), InstanceLock(tmp_path)
    first.acquire()
    try:
        with pytest.raises(RuntimeError, match="already running"):
            second.acquire()
    finally:
        first.release()
    second.acquire()
    second.release()


@pytest.mark.integration
def test_direct_https_workflow_and_process_restart(tmp_path):
    account = "Simple account password 47!"
    master = "Separate simple master passphrase 83!"
    plain = PlainRecord(title="Simple demo", password="dummy-only-secret", notes="ಕನ್ನಡ")
    with LocalBackend(tmp_path) as server:
        first_process = server.process
        api = VaultAPI(server.url, str(server.certs / "ca.crt"))
        try:
            service = VaultService(api)
            service.register("simple@example.test", account)
            service.login("simple@example.test", account)
            service.setup(master)
            record_id = service.save_record(plain)
            service.lock()
            service.unlock(master)
            assert service.records[record_id][1] == plain
            assert api.tls_info["protocol"] == "TLSv1.3"
            metadata = json.loads((tmp_path / "connection.json").read_text())
            assert metadata["observed_tls"]["protocol"] == "TLSv1.3"
            assert master not in json.dumps(metadata)
            wrong = VaultAPI(server.url.replace("localhost", "127.0.0.1"), str(server.certs / "ca.crt"))
            try:
                with pytest.raises(APIError):
                    wrong.request("GET", "/health")
            finally:
                wrong.close()
            service.logout()
        finally:
            api.close()
    assert first_process.poll() is not None
    with LocalBackend(tmp_path) as restarted:
        api = VaultAPI(restarted.url, str(restarted.certs / "ca.crt"))
        try:
            fresh = VaultService(api)
            fresh.login("simple@example.test", account)
            fresh.unlock(master)
            assert fresh.records[record_id][1] == plain
            fresh.logout()
        finally:
            api.close()


@pytest.mark.gui
def test_automatic_gui_start_and_backend_shutdown(tmp_path, monkeypatch):
    import tkinter as tk
    import sys
    from client import gui
    from scripts import local_demo

    try:
        root = tk.Tk()
        root.destroy()
    except tk.TclError:
        pytest.skip("No display available")
    captured = {}
    real_backend = local_demo.LocalBackend
    real_window = gui.VaultWindow

    def backend_factory(_):
        captured["backend"] = real_backend(tmp_path)
        return captured["backend"]

    class AutoCloseWindow(real_window):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            captured["window_opened"] = True
            self.after(100, self.close)

    monkeypatch.setattr(local_demo, "LocalBackend", backend_factory)
    monkeypatch.setattr(gui, "VaultWindow", AutoCloseWindow)
    monkeypatch.setattr(sys, "argv", ["local_demo"])
    local_demo.main()
    assert captured["window_opened"]
    assert captured["backend"].process.poll() is not None
