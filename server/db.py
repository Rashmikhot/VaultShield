from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker


def make_engine(url: str):
    if not url.startswith("sqlite:///"):
        raise ValueError("This MVP supports file-based SQLite only")
    engine = create_engine(
        url, hide_parameters=True, connect_args={"check_same_thread": False, "timeout": 15}
    )

    @event.listens_for(engine, "connect")
    def pragmas(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=15000")

    return engine


def session_factory(engine):
    return sessionmaker(engine, expire_on_commit=False)
