from fastapi.testclient import TestClient
from server.app import create_app
from server.config import Settings


def test_web_frontend_and_assets_are_served(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'web.db'}"))
    with TestClient(app) as client:
        home = client.get("/")
        assert home.status_code == 200
        assert "Cyber Attack Simulation Lab" in home.text
        assert client.get("/web/styles.css").status_code == 200
        js = client.get("/web/app.js")
        assert js.status_code == 200
        assert "runAttack" in js.text
        assert "LIVE BACKEND EXECUTION FLOW" in js.text or "Attack execution flow" in js.text
        assert "execution_logs" in js.text
        assert "before_after" in js.text
    app.state.engine.dispose()
