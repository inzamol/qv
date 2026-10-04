"""Unit tests for SQLAlchemy & SQL Database Analyzer (SQL-001 through SQL-030)."""

from __future__ import annotations

from pathlib import Path

from qv.core.context import (
    CIConfig,
    DependencyDeclaration,
    DockerConfig,
    ImportRecord,
    ProjectContext,
    PythonRuntime,
    SourceFile,
)
from qv.core.models import Severity
from qv.frameworks.sqlalchemy import SqlAlchemyAnalyzer


def make_context(
    source_files: list[tuple[str, str]],
    dependencies: list[str] | None = None,
    imports: list[str] | None = None,
) -> ProjectContext:
    root = Path("/dummy/project")
    sf_objs = [
        SourceFile(
            path=root / rel,
            relative_path=Path(rel),
            content=content,
            is_init=rel.endswith("__init__.py"),
            module_name=rel.replace("/", ".").replace(".py", ""),
        )
        for rel, content in source_files
    ]
    deps = [
        DependencyDeclaration(name=d, specifier="*", source_file=root / "pyproject.toml")
        for d in (dependencies or ["sqlalchemy"])
    ]
    imps = [
        ImportRecord(
            module_name=imp,
            source_file=root / "app.py",
            line_number=1,
            is_relative=False,
        )
        for imp in (imports or ["sqlalchemy"])
    ]
    return ProjectContext(
        project_root=root,
        project_name="sql-app",
        python_runtime=PythonRuntime(version_str="3.12.0", major=3, minor=12, micro=0),
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=tuple(deps),
        installed_packages={},
        source_files=tuple(sf_objs),
        imports=tuple(imps),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )


def test_sql_detection():
    analyzer = SqlAlchemyAnalyzer()

    # Detected via dependency
    ctx_dep = make_context([("app.py", "x = 1")], dependencies=["sqlalchemy"], imports=[])
    assert analyzer.detect(ctx_dep) is True

    # Detected via sqlmodel
    ctx_sqlmodel = make_context([("app.py", "x = 1")], dependencies=["sqlmodel"], imports=[])
    assert analyzer.detect(ctx_sqlmodel) is True

    # Not detected
    ctx_none = make_context(
        [("app.py", "print('hello')")], dependencies=["fastapi"], imports=["fastapi"]
    )
    assert analyzer.detect(ctx_none) is False


def test_sql_001_n_plus_one_query_in_loop():
    code = """
from sqlalchemy.orm import Session
from sqlalchemy import select

def process_users(session: Session, user_ids: list[int]):
    results = []
    for uid in user_ids:
        user = session.get(User, uid)
        results.append(user)
    return results
"""
    ctx = make_context([("db.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    n1_diags = [d for d in diags if d.id == "SQL-001"]
    assert len(n1_diags) == 1
    assert n1_diags[0].severity == Severity.WARNING
    assert "N+1" in n1_diags[0].message


def test_sql_002_session_leak_without_context_manager():
    code = """
from sqlalchemy.orm import sessionmaker

SessionLocal = sessionmaker()

def do_work():
    session = SessionLocal()
    data = session.execute("SELECT 1")
    return data
"""
    ctx = make_context([("work.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    leak_diags = [d for d in diags if d.id == "SQL-002"]
    assert len(leak_diags) == 1
    assert leak_diags[0].severity == Severity.WARNING
    assert "session" in leak_diags[0].message


def test_sql_003_sync_engine_in_async_func():
    code = """
from sqlalchemy import create_engine

async def handle_request():
    engine = create_engine("sqlite:///app.db")
    return engine
"""
    ctx = make_context([("async_db.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    async_diags = [d for d in diags if d.id == "SQL-003"]
    assert len(async_diags) == 1
    assert async_diags[0].severity == Severity.ERROR
    assert "create_engine" in async_diags[0].message


def test_sql_004_sql_injection_string_interpolation():
    code = """
from sqlalchemy import text

def find_user(session, username: str):
    stmt = text(f"SELECT * FROM users WHERE username = '{username}'")
    return session.execute(stmt)
"""
    ctx = make_context([("query.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    inj_diags = [d for d in diags if d.id == "SQL-004"]
    assert len(inj_diags) == 1
    assert inj_diags[0].severity == Severity.ERROR
    assert "SQL injection" in inj_diags[0].message


def test_sql_005_legacy_session_query():
    code = """
from sqlalchemy.orm import Session

def get_active_users(session: Session):
    return session.query(User).filter(User.active == True).all()
"""
    ctx = make_context([("repo.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    query_diags = [d for d in diags if d.id == "SQL-005"]
    assert len(query_diags) >= 1
    assert any(d.id == "SQL-005" for d in diags)


def test_sql_006_missing_relationship_eager_loading_strategy():
    """Test that SQL-006 is reported for relationships lacking an explicit eager loading strategy."""
    code = """
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy import Column, Integer, ForeignKey

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    posts = relationship("Post")

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    user = relationship("User", lazy="selectin")
"""
    ctx = make_context([("models.py", code), ("alembic.ini", "")])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    lazy_diags = [d for d in diags if d.id == "SQL-006"]
    assert len(lazy_diags) == 1
    assert lazy_diags[0].severity == Severity.WARNING
    assert (
        "eager loading" in lazy_diags[0].title.lower()
        or "lazy=" in lazy_diags[0].suggestions[0].description
    )


def test_sql_007_uncommitted_mutation():
    code = """
from sqlalchemy.orm import Session

def create_user(session: Session, new_user):
    session.add(new_user)
    return new_user
"""
    ctx = make_context([("service.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    uncommitted = [d for d in diags if d.id == "SQL-007"]
    assert len(uncommitted) == 1
    assert uncommitted[0].severity == Severity.WARNING
    assert "uncommitted" in uncommitted[0].title.lower() or "commit" in uncommitted[0].message


def test_sql_008_missing_pool_pre_ping():
    code = """
from sqlalchemy import create_engine

engine = create_engine("postgresql+psycopg2://user:pass@localhost:5432/mydb")
"""
    ctx = make_context([("engine.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    ping_diags = [d for d in diags if d.id == "SQL-008"]
    assert len(ping_diags) == 1
    assert ping_diags[0].severity == Severity.WARNING
    assert "pool_pre_ping" in ping_diags[0].message


def test_sql_009_expire_on_commit_in_async_session():
    code = """
from sqlalchemy.ext.asyncio import async_sessionmaker

SessionMaker = async_sessionmaker(expire_on_commit=True)
"""
    ctx = make_context([("async_session.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    expire_diags = [d for d in diags if d.id == "SQL-009"]
    assert len(expire_diags) == 1
    assert expire_diags[0].severity == Severity.WARNING
    assert "expire_on_commit" in expire_diags[0].message


def test_sql_010_hardcoded_credentials_in_url():
    code = """
from sqlalchemy import create_engine

engine = create_engine("postgresql://admin:supersecret123@prod-db.internal:5432/app", pool_pre_ping=True)
"""
    ctx = make_context([("config.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    cred_diags = [d for d in diags if d.id == "SQL-010"]
    assert len(cred_diags) == 1
    assert cred_diags[0].severity == Severity.ERROR
    assert "admin" in cred_diags[0].message


def test_sql_011_unbounded_select_all():
    code = """
from sqlalchemy import select

def list_records(session):
    stmt = select(Record)
    return session.scalars(stmt).all()
"""
    ctx = make_context([("records.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    unbounded = [d for d in diags if d.id == "SQL-011"]
    assert len(unbounded) == 1
    assert unbounded[0].severity == Severity.WARNING
    assert "limit" in unbounded[0].message


def test_sql_012_cascade_delete_without_fk_ondelete():
    code = """
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy import Column, Integer, ForeignKey

class Base(DeclarativeBase):
    pass

class Parent(Base):
    __tablename__ = "parents"
    id = Column(Integer, primary_key=True)
    children = relationship("Child", cascade="all, delete-orphan")

class Child(Base):
    __tablename__ = "children"
    id = Column(Integer, primary_key=True)
    parent_id = Column(Integer, ForeignKey("parents.id"))
"""
    ctx = make_context([("models.py", code), ("alembic.ini", "")])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    cascade_diags = [d for d in diags if d.id == "SQL-012"]
    assert len(cascade_diags) == 1
    assert cascade_diags[0].severity == Severity.INFO
    assert "cascade" in cascade_diags[0].message.lower()


def test_sql_013_flush_inside_loop():
    code = """
def import_items(session, items):
    for item in items:
        session.add(item)
        session.flush()
    session.commit()
"""
    ctx = make_context([("importer.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    flush_diags = [d for d in diags if d.id == "SQL-013"]
    assert len(flush_diags) == 1
    assert flush_diags[0].severity == Severity.WARNING
    assert "flush" in flush_diags[0].message


def test_sql_014_deprecated_declarative_base():
    code = """
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
"""
    ctx = make_context([("base.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    base_diags = [d for d in diags if d.id == "SQL-014"]
    assert len(base_diags) == 1
    assert base_diags[0].severity == Severity.WARNING
    assert "declarative_base" in base_diags[0].message


def test_sql_015_sqlite_missing_check_same_thread():
    code = """
from sqlalchemy import create_engine

engine = create_engine("sqlite:///local.db")
"""
    ctx = make_context([("db_sqlite.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    sqlite_diags = [d for d in diags if d.id == "SQL-015"]
    assert len(sqlite_diags) == 1
    assert sqlite_diags[0].severity == Severity.WARNING
    assert "check_same_thread" in sqlite_diags[0].message


def test_sql_016_missing_alembic_setup():
    code = """
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, Integer

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
"""
    ctx = make_context([("models.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    alembic_diags = [d for d in diags if d.id == "SQL-016"]
    assert len(alembic_diags) == 1
    assert alembic_diags[0].severity == Severity.INFO
    assert "Alembic" in alembic_diags[0].message


def test_sql_017_mapped_column_recommendation():
    code = """
from sqlalchemy.orm import DeclarativeBase, Mapped
from sqlalchemy import Column, Integer

class Base(DeclarativeBase):
    pass

class Item(Base):
    __tablename__ = "items"
    id: Mapped[int] = Column(Integer, primary_key=True)
"""
    ctx = make_context([("models.py", code), ("alembic.ini", "")])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    m_diags = [d for d in diags if d.id == "SQL-017"]
    assert len(m_diags) == 1
    assert m_diags[0].severity == Severity.WARNING
    assert "mapped_column" in m_diags[0].message


def test_sql_018_excessive_pool_size():
    code = """
from sqlalchemy import create_engine

engine = create_engine("postgresql://localhost/db", pool_size=100, pool_pre_ping=True)
"""
    ctx = make_context([("db.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    p_diags = [d for d in diags if d.id == "SQL-018"]
    assert len(p_diags) == 1
    assert p_diags[0].severity == Severity.WARNING
    assert "pool_size" in p_diags[0].message


def test_sql_019_nullpool_in_web_app():
    code = """
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

engine = create_engine("postgresql://localhost/db", poolclass=NullPool, pool_pre_ping=True)
"""
    ctx = make_context([("db.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    np_diags = [d for d in diags if d.id == "SQL-019"]
    assert len(np_diags) == 1
    assert np_diags[0].severity == Severity.WARNING
    assert "NullPool" in np_diags[0].message


def test_sql_020_missing_primary_key():
    code = """
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, String

class Base(DeclarativeBase):
    pass

class LogEntry(Base):
    __tablename__ = "logs"
    message = Column(String)
"""
    ctx = make_context([("models.py", code), ("alembic.ini", "")])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    pk_diags = [d for d in diags if d.id == "SQL-020"]
    assert len(pk_diags) == 1
    assert pk_diags[0].severity == Severity.ERROR
    assert "primary key" in pk_diags[0].message.lower()


def test_sql_021_missing_session_rollback():
    code = """
def update_user(session, user_id):
    try:
        session.add(User(id=user_id))
        session.commit()
    except Exception as e:
        print(f"Error: {e}")
        raise
"""
    ctx = make_context([("service.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    rb_diags = [d for d in diags if d.id == "SQL-021"]
    assert len(rb_diags) == 1
    assert rb_diags[0].severity == Severity.WARNING
    assert "rollback" in rb_diags[0].message


def test_sql_022_large_binary_column():
    code = """
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, Integer, LargeBinary

class Base(DeclarativeBase):
    pass

class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True)
    payload = Column(LargeBinary)
"""
    ctx = make_context([("models.py", code), ("alembic.ini", "")])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    blob_diags = [d for d in diags if d.id == "SQL-022"]
    assert len(blob_diags) == 1
    assert blob_diags[0].severity == Severity.INFO
    assert "LargeBinary" in blob_diags[0].message


def test_sql_023_foreign_key_missing_index():
    code = """
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, Integer, ForeignKey

class Base(DeclarativeBase):
    pass

class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True)
    customer_id = Column(Integer, ForeignKey("customers.id"))
"""
    ctx = make_context([("models.py", code), ("alembic.ini", "")])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    fk_diags = [d for d in diags if d.id == "SQL-023"]
    assert len(fk_diags) == 1
    assert fk_diags[0].severity == Severity.WARNING
    assert "index" in fk_diags[0].message


def test_sql_024_insecure_remote_db_url():
    code = """
from sqlalchemy import create_engine

engine = create_engine("postgresql://user:pass@db.example.com:5432/production", pool_pre_ping=True)
"""
    ctx = make_context([("config.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    ssl_diags = [d for d in diags if d.id == "SQL-024"]
    assert len(ssl_diags) == 1
    assert ssl_diags[0].severity == Severity.WARNING
    assert "SSL" in ssl_diags[0].message or "ssl" in ssl_diags[0].message.lower()


def test_sql_025_deprecated_engine_execute():
    code = """
from sqlalchemy import create_engine

engine = create_engine("sqlite:///app.db", connect_args={"check_same_thread": False})

def run_query():
    return engine.execute("SELECT 1")
"""
    ctx = make_context([("db.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    exec_diags = [d for d in diags if d.id == "SQL-025"]
    assert len(exec_diags) == 1
    assert exec_diags[0].severity == Severity.ERROR
    assert "engine.execute" in exec_diags[0].message


def test_sql_026_async_session_leak():
    code = """
from sqlalchemy.ext.asyncio import async_sessionmaker

AsyncSessionLocal = async_sessionmaker()

async def fetch_data():
    session = AsyncSessionLocal()
    data = await session.execute("SELECT 1")
    return data
"""
    ctx = make_context([("async_repo.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    async_leak = [d for d in diags if d.id == "SQL-026"]
    assert len(async_leak) == 1
    assert async_leak[0].severity == Severity.WARNING
    assert "AsyncSession" in async_leak[0].message


def test_sql_027_unsafe_concurrent_balance_update():
    code = """
from sqlalchemy import select

def debit_account(session, account_id: int, amount: float):
    account = session.scalars(select(Account).where(Account.id == account_id)).first()
    account.balance -= amount
    session.commit()
"""
    ctx = make_context([("billing.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    race_diags = [d for d in diags if d.id == "SQL-027"]
    assert len(race_diags) == 1
    assert race_diags[0].severity == Severity.WARNING
    assert "with_for_update" in race_diags[0].message


def test_sql_028_scoped_session_in_async():
    code = """
from sqlalchemy.orm import scoped_session, sessionmaker

async def handle_request():
    db = scoped_session(sessionmaker())
    return db
"""
    ctx = make_context([("async_handler.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    scoped_diags = [d for d in diags if d.id == "SQL-028"]
    assert len(scoped_diags) == 1
    assert scoped_diags[0].severity == Severity.ERROR
    assert "scoped_session" in scoped_diags[0].message


def test_sql_029_missing_tablename():
    code = """
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, Integer

class Base(DeclarativeBase):
    pass

class Product(Base):
    id = Column(Integer, primary_key=True)
"""
    ctx = make_context([("models.py", code), ("alembic.ini", "")])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    table_diags = [d for d in diags if d.id == "SQL-029"]
    assert len(table_diags) == 1
    assert table_diags[0].severity == Severity.ERROR
    assert "__tablename__" in table_diags[0].message


def test_sql_030_raw_connection_leak():
    code = """
from sqlalchemy import create_engine

engine = create_engine("sqlite:///test.db", connect_args={"check_same_thread": False})

def do_low_level():
    raw_conn = engine.raw_connection()
    return raw_conn
"""
    ctx = make_context([("low_level.py", code)])
    analyzer = SqlAlchemyAnalyzer()
    diags = analyzer.analyze(ctx)

    raw_diags = [d for d in diags if d.id == "SQL-030"]
    assert len(raw_diags) == 1
    assert raw_diags[0].severity == Severity.WARNING
    assert "raw_connection" in raw_diags[0].message
