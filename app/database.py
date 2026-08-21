"""Database session plumbing."""
from __future__ import annotations

import logging

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

logger = logging.getLogger("douglas.db")

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    pool_pre_ping=True,
)

if settings.database_url.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        # WAL keeps the console readable while an agent is uploading results.
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _add_missing_columns() -> None:
    """Add columns that exist in the models but not yet in the database.

    create_all() makes new tables but never touches an existing one, so a
    console upgraded in place kept the old schema and every query touching a
    new column failed — the host detail panel, and with it the button to
    remove a host, simply returned 500.

    Deliberately additive only: nothing is dropped, renamed or retyped, so a
    downgrade still reads the file and no data is ever lost to a migration.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue  # create_all just made it, so it is current

            present = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in present:
                    continue

                ddl = f"{column.name} {column.type.compile(engine.dialect)}"

                # A NOT NULL column cannot be added to a table with rows unless
                # it carries a default, so give it one or relax the constraint.
                default = getattr(column, "default", None)
                if default is not None and getattr(default, "is_scalar", False):
                    value = default.arg
                    if isinstance(value, bool):
                        ddl += f" DEFAULT {1 if value else 0}"
                    elif isinstance(value, (int, float)):
                        ddl += f" DEFAULT {value}"
                    elif isinstance(value, str):
                        escaped = value.replace("'", "''")
                        ddl += f" DEFAULT '{escaped}'"

                try:
                    conn.execute(text(f"ALTER TABLE {table.name} ADD COLUMN {ddl}"))
                    logger.info("Schema: added %s.%s", table.name, column.name)
                except Exception as exc:  # noqa: BLE001
                    # Report and carry on. One column that cannot be added is
                    # better than a console that refuses to start.
                    logger.warning("Schema: could not add %s.%s (%s)",
                                   table.name, column.name, exc)


def init_db() -> None:
    from . import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(bind=engine)
    _add_missing_columns()
