import time
import tkinter as tk
import pytest
from client.gui import VaultWindow
from shared.schemas import PlainRecord
from tests.test_client import ready


@pytest.mark.gui
def test_gui_screens_mask_and_auto_lock(backend, monkeypatch):
    try:
        probe = tk.Tk()
        probe.destroy()
    except tk.TclError:
        pytest.skip("No graphical display; run this test on Windows or under Xvfb")
    _, c, _, _ = backend
    service = ready(c)
    rid = service.save_record(PlainRecord(title="GUI sample", password="dummy-gui-secret"))
    app = VaultWindow(service, timeout=30)
    app.withdraw()
    try:
        app.show_records()
        app.update()
        assert app.tree.item(rid)["values"][0] == "GUI sample"
        app.show_editor(rid)
        app.update()
        entries = [w for w in app.body.winfo_children() if w.winfo_class() == "TEntry"]
        assert any(str(e.cget("show")) == "*" for e in entries)
        app.show_master_change()
        app.update()
        app.show_password_change()
        app.update()
        app.show_security()
        app.update()
        app.show_records()
        app.last_activity = time.monotonic() - 31
        app.tick()
        app.update()
        assert service.key is None and not service.records
        app.show_setup()
        app.update()
        app.show_login()
        app.update()
    finally:
        app.pool.shutdown(wait=True, cancel_futures=True)
        app.destroy()
