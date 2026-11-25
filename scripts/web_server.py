"""Loopback-only HTTP server for the browser edition."""
import os
from pathlib import Path
import argparse
import uvicorn
from alembic import command
from alembic.config import Config
from server.app import create_app
from server.config import Settings

def run(data_dir: Path, port: int):
    data_dir = data_dir.resolve()
    url = "sqlite:///" + (data_dir / "vaultshield.db").as_posix()
    os.environ["VS_DATABASE_URL"] = url
    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")
    app = create_app(Settings(database_url=url))
    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning", access_log=False,
                    server_header=False, proxy_headers=False)
    finally:
        app.state.engine.dispose()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    run(args.data_dir, args.port)
