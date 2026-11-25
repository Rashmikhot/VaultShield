import os
from alembic import context
from server.models import Base
from server.db import make_engine

config = context.config
url = os.getenv("VS_DATABASE_URL", config.get_main_option("sqlalchemy.url"))
if context.is_offline_mode():
    context.configure(url=url, target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = make_engine(url)
    with engine.connect() as connection:
        context.configure(
            connection=connection, target_metadata=Base.metadata, compare_type=True, render_as_batch=True
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()
