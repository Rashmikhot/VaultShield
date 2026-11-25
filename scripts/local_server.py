"""Local-only HTTPS API, served directly by Uvicorn. No gateway or container."""

import argparse
import os
import ssl
from pathlib import Path
import uvicorn
from alembic import command
from alembic.config import Config
from server.app import create_app
from server.config import Settings


def server_context(certs):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_ecdh_curve("prime256v1")
    context.options |= ssl.OP_NO_TICKET
    context.num_tickets = 0
    context.keylog_filename = None
    context.load_cert_chain(str(certs / "server.crt"), str(certs / "server.key"))
    # Python/OpenSSL negotiates a supported TLS 1.3 suite. The client displays the actual suite.
    return context


def run(data_dir, port):
    data_dir = Path(data_dir).resolve()
    url = "sqlite:///" + (data_dir / "vaultshield.db").as_posix()
    # Override any unrelated shell database setting: this runner owns only its demo directory.
    os.environ["VS_DATABASE_URL"] = url
    config = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    tls = server_context(data_dir / "certs")
    application = create_app(Settings(database_url=url))
    configuration = uvicorn.Config(
        application,
        host="127.0.0.1",
        port=port,
        workers=1,
        access_log=False,
        log_level="warning",
        proxy_headers=False,
        server_header=False,
        timeout_graceful_shutdown=5,
        ssl_context_factory=lambda _config, _default: tls,
    )
    try:
        uvicorn.Server(configuration).run()
    finally:
        application.state.engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    run(args.data_dir, args.port)
