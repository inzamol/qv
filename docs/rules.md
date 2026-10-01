# Diagnostic Rules Catalog

`qv` rule IDs are stable public identifiers. This catalog lists all supported diagnostic checks, their default severities, and remediation strategies.

---

## 1. Dependency Rules

### 1.1 DEP-001: Dependency Constraint Conflict
- **Default Severity:** `ERROR`
- **Description:** Two or more declared or transitive dependencies have incompatible version constraints.
- **Remediation:** Upgrade the conflicting package or loosen the version pin to satisfy all requirements.

### 1.2 DEP-002: Missing Dependency Declaration
- **Default Severity:** `ERROR`
- **Description:** A third-party package is imported in project source code but is not declared in `pyproject.toml` or requirements files.
- **Remediation:** Add the missing package to your project dependencies (`uv add <package>` or `pip install <package>`).

### 1.3 DEP-003: Unused Declared Dependency
- **Default Severity:** `WARNING`
- **Description:** A package is declared as a direct dependency, but no import statements were detected across project source files.
- **Remediation:** Verify if this dependency is required at runtime or remove it to keep dependencies lean.

### 1.4 DEP-004: Python Compatibility Mismatch
- **Default Severity:** `WARNING`
- **Description:** A package requires a Python version incompatible with the target project runtime.
- **Remediation:** Upgrade your target Python version or install a version of the package compatible with your environment.

### 1.5 DEP-005: Installed/Declaration Mismatch
- **Default Severity:** `WARNING`
- **Description:** The package version installed in the virtualenv does not satisfy the constraint declared in your project manifest.
- **Remediation:** Synchronize your virtual environment using `uv sync`, `poetry install`, or `pip install -r requirements.txt`.

### 1.6 DEP-006: Vulnerable Transitive Dependency
- **Default Severity:** `ERROR`
- **Description:** A security vulnerability has been identified in a direct or transitive dependency.
- **Remediation:** Update the vulnerable dependency or apply security patches.

---

## 2. Environment & Drift Rules

### 2.1 ENV-001: Python Version Drift
- **Default Severity:** `WARNING`
- **Description:** The active Python interpreter version differs from the project's target runtime specification.
- **Remediation:** Rebuild your virtual environment using the configured target Python version.

### 2.2 ENV-002: Docker Runtime Drift
- **Default Severity:** `WARNING`
- **Description:** The Python version specified in `Dockerfile` or `compose.yml` differs from the project's target runtime.
- **Remediation:** Update the base image tag in `Dockerfile` (e.g. `FROM python:3.12-slim`).

### 2.3 ENV-003: CI Runtime Drift
- **Default Severity:** `WARNING`
- **Description:** CI workflow matrix does not test the Python versions declared in project support.
- **Remediation:** Align your CI test matrix with `pyproject.toml` supported versions.

---

## 3. Import & Architecture Rules

### 3.1 IMP-001: Circular Import Detected
- **Default Severity:** `ERROR`
- **Description:** An import cycle exists between two or more local modules, risking runtime `ImportError` or partially initialized modules.
- **Remediation:** Break the cycle by refactoring shared logic into a separate module or using deferred imports inside functions.

### 3.2 IMP-002: Unresolved Local Import
- **Default Severity:** `ERROR`
- **Description:** A local module imported in source code could not be resolved on the project's Python path.
- **Remediation:** Check the module name and ensure source directories are on the Python path or package root.

### 3.3 IMP-003: Unused / Orphan Local Module
- **Default Severity:** `WARNING`
- **Description:** A Python source file exists in the project but is never imported or referenced by any other module, entry point, or test file.
- **Remediation:** Review if the module is dead/obsolete and can be safely removed, or export it in package `__init__.py`.

### 3.4 IMP-004: Deprecated or Removed Standard Library Module
- **Default Severity:** `ERROR`
- **Description:** A standard library module imported in source code was deprecated or removed in modern Python 3.11-3.13 (PEP 594).
- **Remediation:** Replace the removed stdlib module with its modern replacement (e.g. `importlib` instead of `imp`, `subprocess` instead of `pipes`).

---

## 4. Packaging Rules

### 4.1 PKG-001: Missing Package Metadata
- **Default Severity:** `WARNING`
- **Description:** Essential packaging metadata (such as project name, version, or description) is missing from `pyproject.toml`.
- **Remediation:** Provide standard PEP 621 fields under the `[project]` table.

### 4.2 PKG-002: Invalid Project Configuration
- **Default Severity:** `ERROR`
- **Description:** `pyproject.toml` contains syntax errors or invalid configuration tables.
- **Remediation:** Fix TOML syntax and ensure configuration follows PEP 621 specifications.

---

## 5. FastAPI Framework Rules (`FAP-xxx`)

### 5.1 FAP-001: Blocking Call or CPU-Bound Operation in Async Endpoint
- **Default Severity:** `ERROR`
- **Description:** Synchronous blocking operations (such as `time.sleep()`, synchronous `requests`, `urllib.request.urlopen()`, `subprocess.run()`, or synchronous database queries) or heavy CPU-bound hashing (`bcrypt.hashpw`, `passlib`, `hashlib.pbkdf2_hmac`) called inside an `async def` FastAPI route handler stall the entire asyncio event loop.
- **Remediation:** Use async non-blocking alternatives (e.g. `asyncio.sleep()`, `httpx.AsyncClient()`), delegate work to worker threads via `anyio.to_thread.run_sync()`, or declare the route as regular synchronous `def` so FastAPI executes it in a worker threadpool.

### 5.2 FAP-002: Blocking Dependency in Async Path
- **Default Severity:** `WARNING`
- **Description:** An `async def` route handler depends on a dependency (`Depends(...)`) that executes synchronous blocking I/O calls or CPU-heavy computations.
- **Remediation:** Refactor the dependency function to use non-blocking async libraries or wrap blocking logic with a threadpool executor.

### 5.3 FAP-003: Missing Response Model or Return Type Annotation
- **Default Severity:** `WARNING`
- **Description:** FastAPI route handler does not declare a `response_model` argument in its route decorator or provide a return type annotation, disabling OpenAPI schema generation and automated response serialization/filtering.
- **Remediation:** Add a return type annotation (`def get_item(...) -> ItemResponse:`) or set `response_model=ItemResponse` in the decorator.

### 5.4 FAP-004: Insecure CORS or Debug Configuration
- **Default Severity:** `ERROR`
- **Description:** `CORSMiddleware` configured with wildcard `allow_origins=["*"]` and `allow_credentials=True`, insecure plaintext HTTP `tokenUrl` in `OAuth2PasswordBearer`, or FastAPI application instantiated with `debug=True`. Wildcard origins with credentials violate browser security policies and expose authentication state.
- **Remediation:** Specify explicit trusted origins when credentials are enabled, use HTTPS or relative paths for OAuth2 token URLs, and disable debug mode in production.

### 5.5 FAP-005: Missing HTTP Client Timeout Configuration
- **Default Severity:** `WARNING`
- **Description:** HTTP client (such as `httpx.AsyncClient`, `httpx.Client`, or `aiohttp.ClientSession`) instantiated without an explicit timeout or with `timeout=None`.
- **Remediation:** Pass an explicit timeout parameter (e.g. `httpx.AsyncClient(timeout=10.0)`) to prevent hung connections and resource starvation.

### 5.6 FAP-006: Route Path Parameter Template Mismatch
- **Default Severity:** `ERROR`
- **Description:** A path parameter defined in the route URL template (e.g. `@app.get("/users/{user_id}")`) does not match any parameter in the handler function signature, causing runtime 422 Unprocessable Entity errors.
- **Remediation:** Ensure all `{param}` placeholders in route URL decorators match parameter names in the endpoint function signature.

### 5.7 FAP-007: Unsafe Yield Dependency Without Try/Finally
- **Default Severity:** `WARNING`
- **Description:** A generator dependency using `yield` does not wrap cleanup code in a `try...finally` block. If an exception occurs during request processing, teardown code after `yield` will not execute, leading to database connection or resource leaks.
- **Remediation:** Wrap the `yield` and teardown cleanup inside a `try...finally` block.

### 5.8 FAP-008: Deprecated `@app.on_event` Lifecycle Hook
- **Default Severity:** `WARNING`
- **Description:** Using deprecated `@app.on_event("startup")` or `@app.on_event("shutdown")` event hooks instead of modern lifespan context managers.
- **Remediation:** Migrate lifecycle logic to `@asynccontextmanager async def lifespan(app: FastAPI)` and pass `lifespan` to `FastAPI(lifespan=lifespan)`.

### 5.9 FAP-009: Untyped or Unvalidated Request Body
- **Default Severity:** `WARNING`
- **Description:** Route handler accepts an untyped parameter (such as `dict`, `Any`, or untyped `Body(...)`) instead of a strict Pydantic model, bypassing schema validation and API documentation.
- **Remediation:** Create a Pydantic `BaseModel` schema and use it as the type annotation for request payloads.

### 5.10 FAP-010: Shadowed or Duplicate Route Endpoint
- **Default Severity:** `ERROR`
- **Description:** Multiple route handlers register the same HTTP method and path on the same router/app instance, causing one endpoint to silently shadow the other.
- **Remediation:** Ensure all routes have distinct paths or combine the logic into a single handler.

### 5.11 FAP-011: Mutable Default Value in Route Parameter
- **Default Severity:** `WARNING`
- **Description:** Route handler parameter uses a mutable default value (such as `list`, `dict`, or `set`), which can leak state across concurrent requests.
- **Remediation:** Use `None` as the default value (e.g. `filters: list[str] | None = None`) or use `Field(default_factory=list)`.

### 5.12 FAP-012: Invalid Exception Handler Signature
- **Default Severity:** `ERROR`
- **Description:** Custom `@app.exception_handler` function does not accept the required `(request: Request, exc: Exception)` signature, causing runtime crashes when exceptions occur.
- **Remediation:** Update the handler function signature to accept exactly `(request: Request, exc: Exception)`.

### 5.13 FAP-013: Untracked `asyncio.create_task` in Route Handler
- **Default Severity:** `WARNING`
- **Description:** Spawning raw `asyncio.create_task()` directly inside route handlers without background task management, which can lead to unhandled crashes or premature task collection.
- **Remediation:** Use FastAPI's built-in `BackgroundTasks` (`background_tasks.add_task(...)`) for reliable request-scoped task execution.

### 5.14 FAP-014: Potential Path Traversal in `FileResponse`
- **Default Severity:** `WARNING`
- **Description:** Passing an unsanitized path parameter or query string directly to `FileResponse()`, creating an arbitrary file read vulnerability.
- **Remediation:** Validate that the resolved file path is inside an allowed base directory using `path.is_relative_to(base_dir)`.

### 5.15 FAP-015: Blocking File I/O in Async Endpoint
- **Default Severity:** `ERROR`
- **Description:** Synchronous `open()`, `.read()`, or `.write()` calls inside `async def` routes block the asyncio event loop.
- **Remediation:** Use `aiofiles`, `anyio.Path`, or run file operations in a synchronous `def` route.

### 5.16 FAP-016: Sensitive Field Exposure in Schema
- **Default Severity:** `ERROR`
- **Description:** Pydantic model declares sensitive fields (e.g. `password`, `hashed_password`, `secret_key`) without `Field(exclude=True)` or output filtering.
- **Remediation:** Exclude sensitive fields from output schemas or mark them with `Field(exclude=True)`.

### 5.17 FAP-017: Non-Standard HTTP Status Code on POST or DELETE
- **Default Severity:** `WARNING`
- **Description:** `@app.post(...)` or `@app.delete(...)` routes return `200 OK` by default instead of explicit REST status codes (`201 Created` or `204 No Content`).
- **Remediation:** Declare `status_code=status.HTTP_201_CREATED` or `status.HTTP_204_NO_CONTENT`.

### 5.18 FAP-018: Global In-Memory State Mutation in Route Handler
- **Default Severity:** `ERROR`
- **Description:** Mutating module-level global variables or dictionaries inside route handlers without locks causes concurrency race conditions.
- **Remediation:** Persist shared state in a database/cache or guard operations with `asyncio.Lock`.

### 5.19 FAP-019: Insecure Cookie Configuration
- **Default Severity:** `ERROR`
- **Description:** `response.set_cookie()` called with `httponly=False` or `secure=False`, leaving authentication cookies vulnerable to XSS and interception.
- **Remediation:** Always set `httponly=True` and `secure=True` for authentication and session cookies.

### 5.20 FAP-020: Potential Open Redirect in `RedirectResponse`
- **Default Severity:** `WARNING`
- **Description:** Initializing `RedirectResponse` directly with user-supplied URL inputs without whitelist validation.
- **Remediation:** Verify that redirect URLs are relative paths or match an allowed domain whitelist.

### 5.21 FAP-021: Router Included Without Tags or Prefix
- **Default Severity:** `WARNING`
- **Description:** `app.include_router()` called without `tags` or `prefix`, leading to disorganized OpenAPI documentation.
- **Remediation:** Specify `prefix` and `tags` when mounting routers.

### 5.22 FAP-022: WebSocket Route Missing `await websocket.accept()`
- **Default Severity:** `ERROR`
- **Description:** WebSocket route handler attempts to process messages before completing the connection handshake with `await websocket.accept()`.
- **Remediation:** Call `await websocket.accept()` before reading or writing data.

### 5.23 FAP-023: Deprecated Pydantic v1 `class Config`
- **Default Severity:** `WARNING`
- **Description:** Using legacy inner `class Config:` inside Pydantic models instead of modern `model_config = ConfigDict(...)`.
- **Remediation:** Migrate inner configuration to `model_config = ConfigDict(...)`.

### 5.24 FAP-024: Redundant Duplicate Dependency Declaration
- **Default Severity:** `WARNING`
- **Description:** Multiple parameters in the same route handler declare identical `Depends(...)` targets.
- **Remediation:** Consolidate redundant dependencies into a single parameter.

### 5.25 FAP-025: Returned HTTPException Instance Instead of Raise
- **Default Severity:** `ERROR`
- **Description:** Returning an `HTTPException` instance in a route handler returns a `200 OK` HTTP response with the serialized exception object instead of raising an error.
- **Remediation:** Use `raise HTTPException(...)` instead of `return HTTPException(...)`.

### 5.26 FAP-026: Deprecated Pydantic v1 `@validator` or `@root_validator`
- **Default Severity:** `WARNING`
- **Description:** Using deprecated Pydantic v1 `@validator` or `@root_validator` decorators instead of modern Pydantic v2 `@field_validator` or `@model_validator`.
- **Remediation:** Migrate to `@field_validator` or `@model_validator` from `pydantic`.

### 5.27 FAP-027: Dependency Parameter Missing Type Annotation
- **Default Severity:** `WARNING`
- **Description:** Route parameter initialized with `Depends(...)`, `Query(...)`, or `Path(...)` does not specify a type annotation, disabling schema generation and static type checking.
- **Remediation:** Add an explicit type annotation (e.g. `param: Type = Depends(...)` or `param: Annotated[Type, Depends(...)]`).

### 5.28 FAP-028: Raw `json.loads` Called on Request Body
- **Default Severity:** `WARNING`
- **Description:** Calling `json.loads(await request.body())` is an anti-pattern when FastAPI/Starlette provide the optimized built-in `await request.json()` method.
- **Remediation:** Replace `json.loads(await request.body())` with `await request.json()`.

### 5.29 FAP-029: StreamingResponse Initialized Without `media_type`
- **Default Severity:** `WARNING`
- **Description:** Instantiating `StreamingResponse` without specifying `media_type` can cause clients to misinterpret the streamed content format.
- **Remediation:** Pass an explicit `media_type` argument (e.g. `StreamingResponse(stream, media_type='application/json')`).

### 5.30 FAP-030: Missing Route Summary or Docstring for OpenAPI Documentation
- **Default Severity:** `WARNING`
- **Description:** Public route endpoint does not provide a docstring, `summary`, or `description`, resulting in sparse and incomplete OpenAPI documentation.
- **Remediation:** Add a function docstring or pass `summary=...` in the route decorator.

### 5.31 FAP-031: Prefer `typing.Annotated` Over Parameter Default Assignment
- **Default Severity:** `INFO`
- **Description:** Using default parameter assignments (e.g. `db: Session = Depends(...)`) can cause issues with type checkers and testing. Modern FastAPI strongly recommends `Annotated[Session, Depends(...)]`.
- **Remediation:** Refactor parameter to `param: Annotated[Type, Depends(...)]`.

### 5.32 FAP-032: Redundant `jsonable_encoder` With `response_model`
- **Default Severity:** `WARNING`
- **Description:** Calling `jsonable_encoder()` in a route handler that already specifies `response_model` causes redundant double serialization, reducing throughput.
- **Remediation:** Return raw objects/dictionaries and allow FastAPI's `response_model` to handle serialization.

### 5.33 FAP-033: Missing `from_attributes=True` in ORM Response Schema
- **Default Severity:** `WARNING`
- **Description:** Pydantic response models for ORM/database entities missing `model_config = ConfigDict(from_attributes=True)` trigger validation errors at runtime.
- **Remediation:** Add `model_config = ConfigDict(from_attributes=True)` to the schema.

### 5.34 FAP-034: Missing `await` on `request.json()` or `request.body()`
- **Default Severity:** `ERROR`
- **Description:** Calling `request.json()` or `request.body()` without `await` inside an `async def` handler assigns an un-awaited coroutine object instead of the payload.
- **Remediation:** Add `await` before `request.json()` or `request.body()`.

### 5.35 FAP-035: Raw `Exception` Raised Instead of `HTTPException`
- **Default Severity:** `WARNING`
- **Description:** Raising generic `Exception`, `ValueError`, or `RuntimeError` produces unhandled `500 Internal Server Error` responses instead of structured REST responses.
- **Remediation:** Raise `HTTPException(status_code=..., detail=...)`.

### 5.36 FAP-036: Mutating `app.state` Inside Route Handler
- **Default Severity:** `WARNING`
- **Description:** Mutating `request.app.state` or `app.state` in per-request handlers introduces concurrency race conditions.
- **Remediation:** Initialize shared state during `lifespan` startup.

### 5.37 FAP-037: `SecurityScopes` Declared With `Depends` Instead of `Security`
- **Default Severity:** `WARNING`
- **Description:** Declaring a `SecurityScopes` parameter with `Depends(...)` does not pass scopes. Use `Security(..., scopes=[...])`.
- **Remediation:** Use `Security(dependency, scopes=[...])`.

### 5.38 FAP-038: Hardcoded HTTP Status Code Integer
- **Default Severity:** `INFO`
- **Description:** Using integer literals for `status_code` (e.g. `status_code=201`) reduces readability compared to `status.HTTP_201_CREATED`.
- **Remediation:** Import `status` from `fastapi` and use named constants (e.g. `status.HTTP_201_CREATED`).

---

## 6. SQLAlchemy & SQL Database Rules

### 6.1 SQL-001: Potential N+1 Database Query in Loop
- **Default Severity:** `WARNING`
- **Description:** Executing queries (`session.execute`, `session.query`, `session.get`) inside `for` or `while` loops triggers N+1 database roundtrips.
- **Remediation:** Batch load records using `where(Model.id.in_(ids))` or configure eager loading with `joinedload`/`selectinload`.

### 6.2 SQL-002: Session Instantiated Without Context Manager or Cleanup
- **Default Severity:** `WARNING`
- **Description:** Creating a `Session` or `SessionLocal()` without a `with` block or `try...finally: session.close()` leaks active database connections.
- **Remediation:** Use `with SessionLocal() as session:` or a dependency yield pattern.

### 6.3 SQL-003: Synchronous DB Operation in Async Event Loop
- **Default Severity:** `ERROR`
- **Description:** Invoking synchronous `create_engine()` or synchronous session operations inside `async def` functions blocks the event loop.
- **Remediation:** Use `create_async_engine()` and `AsyncSession` with async drivers (e.g. `asyncpg`, `aiosqlite`).

### 6.4 SQL-004: Raw SQL String Interpolation (SQL Injection Risk)
- **Default Severity:** `ERROR`
- **Description:** Formatting SQL query strings using f-strings, `%`, or `.format()` inside `text()` or `cursor.execute()` introduces critical SQL injection vulnerabilities.
- **Remediation:** Use bound parameters (`text("SELECT * FROM users WHERE id = :id"), {"id": user_val}`).

### 6.5 SQL-005: Legacy SQLAlchemy 1.x `session.query()` Syntax
- **Default Severity:** `WARNING`
- **Description:** Using legacy `session.query(...)` in SQLAlchemy 2.0 projects instead of 2.0-style `select()` statements.
- **Remediation:** Migrate to `session.scalars(select(Model).where(...))`.

### 6.6 SQL-006: Missing Relationship Eager Loading Strategy in Async Session
- **Default Severity:** `WARNING`
- **Description:** Accessing lazy-loaded ORM relationships in async sessions triggers `MissingGreenlet` errors at runtime.
- **Remediation:** Configure `lazy="selectin"` on relationships or apply `.options(selectinload(Model.relation))`.

### 6.7 SQL-007: Uncommitted Transaction in Mutation Function
- **Default Severity:** `WARNING`
- **Description:** A function calls `session.add(...)` or `session.delete(...)` but never executes `session.commit()` or `with session.begin():`.
- **Remediation:** Call `session.commit()` or wrap in `with session.begin():`.

### 6.8 SQL-008: `create_engine` Missing `pool_pre_ping` Connection Health Check
- **Default Severity:** `WARNING`
- **Description:** Database engines created without `pool_pre_ping=True` risk stale connection disconnects when idle connections are closed by servers/firewalls.
- **Remediation:** Add `pool_pre_ping=True` to `create_engine()` / `create_async_engine()`.

### 6.9 SQL-009: `expire_on_commit=True` in `AsyncSession`
- **Default Severity:** `WARNING`
- **Description:** Leaving `expire_on_commit=True` in `AsyncSession` or `async_sessionmaker` causes `MissingGreenlet` errors when accessing committed model attributes.
- **Remediation:** Specify `expire_on_commit=False`.

### 6.10 SQL-010: Hardcoded Database Credentials in Connection URL
- **Default Severity:** `ERROR`
- **Description:** Plaintext passwords and connection secrets are committed directly into Python source code.
- **Remediation:** Load database credentials from environment variables (`os.getenv("DATABASE_URL")`).

### 6.11 SQL-011: Unbounded `SELECT` Query Without Limit or Pagination
- **Default Severity:** `WARNING`
- **Description:** Calling `.all()` on database queries without `.limit()` or pagination clauses risks out-of-memory crashes on large tables.
- **Remediation:** Add `.limit(PAGE_SIZE)` and pagination parameters.

### 6.12 SQL-012: Relationship Cascade Delete Without ForeignKey `ondelete="CASCADE"`
- **Default Severity:** `INFO`
- **Description:** `cascade="all, delete-orphan"` on ORM relationships without database-level `ondelete="CASCADE"` on the foreign key forces slow Python-side row-by-row deletion.
- **Remediation:** Add `ondelete="CASCADE"` to the `ForeignKey` definition.

### 6.13 SQL-013: Session Flush or Commit Called Inside Loop
- **Default Severity:** `WARNING`
- **Description:** Calling `session.flush()` or `session.commit()` inside tight loops creates excessive database network roundtrips.
- **Remediation:** Commit once after the loop or use bulk insert statements (`session.execute(insert(Model), batch)`).

### 6.14 SQL-014: Deprecated `declarative_base()` Function
- **Default Severity:** `WARNING`
- **Description:** Using legacy `Base = declarative_base()` instead of modern SQLAlchemy 2.0 `class Base(DeclarativeBase): pass`.
- **Remediation:** Subclass `DeclarativeBase` from `sqlalchemy.orm`.

### 6.15 SQL-015: SQLite Engine Missing `check_same_thread=False` in Multi-Threaded Application
- **Default Severity:** `WARNING`
- **Description:** Using SQLite engines across threads in web servers without `connect_args={"check_same_thread": False}` causes `ProgrammingError`.
- **Remediation:** Set `connect_args={"check_same_thread": False}` when instantiating SQLite engines.

### 6.16 SQL-016: Missing Database Migration Configuration (Alembic)
- **Default Severity:** `INFO`
- **Description:** SQLAlchemy ORM models are declared in the codebase, but no Alembic migrations directory or `alembic.ini` file exists.
- **Remediation:** Initialize database migrations using `alembic init alembic`.

### 6.17 SQL-017: `Mapped[...]` Attribute Missing `mapped_column()` in 2.0 Declarative Model
- **Default Severity:** `WARNING`
- **Description:** Using legacy `Column(...)` or untyped field definitions alongside `Mapped[...]` type annotations in SQLAlchemy 2.0 declarative models.
- **Remediation:** Replace `col: Mapped[int] = Column(Integer)` with `col: Mapped[int] = mapped_column()`.

### 6.18 SQL-018: Excessive Connection Pool Size in Single Application Instance
- **Default Severity:** `WARNING`
- **Description:** Configuring `create_engine` with `pool_size` or `max_overflow` > 50 in a single application worker risks exhausting database `max_connections`.
- **Remediation:** Keep `pool_size` between 5 and 20 per worker and scale using an external connection pooler like pgBouncer.

### 6.19 SQL-019: `NullPool` Configured in Persistent Web Application
- **Default Severity:** `WARNING`
- **Description:** Setting `poolclass=NullPool` in a persistent web server disables connection pooling, forcing a new TCP handshake and SSL negotiation on every request.
- **Remediation:** Use default `QueuePool` for persistent web applications; reserve `NullPool` for ephemeral AWS Lambda/serverless environments.

### 6.20 SQL-020: Declarative ORM Model Missing Primary Key Definition
- **Default Severity:** `ERROR`
- **Description:** A concrete model inheriting from `Base` / `DeclarativeBase` does not declare a primary key column, causing runtime ORM identity map failures.
- **Remediation:** Mark at least one column with `primary_key=True` or `mapped_column(primary_key=True)`.

### 6.21 SQL-021: Missing `session.rollback()` in Database Exception Handler
- **Default Severity:** `WARNING`
- **Description:** An `except` block catches errors around database operations but fails to call `session.rollback()`, leaving the session in an unusable invalid transaction state.
- **Remediation:** Add `session.rollback()` inside `except` handlers or wrap operations in `with session.begin():`.

### 6.22 SQL-022: Large Binary or Heavy Text Column Without `deferred()` Strategy
- **Default Severity:** `INFO`
- **Description:** Model includes heavy `LargeBinary`, `BLOB`, or `BYTEA` columns that are eagerly loaded on every `SELECT *`, consuming excessive application memory.
- **Remediation:** Wrap the column in `deferred(Column(LargeBinary))` or use `.options(load_only(...))`.

### 6.23 SQL-023: `ForeignKey` Column Defined Without `index=True`
- **Default Severity:** `WARNING`
- **Description:** Foreign key column created without an index, resulting in slow sequential table scans during `JOIN` queries, foreign key lookups, and cascade operations.
- **Remediation:** Add `index=True` to ForeignKey column definitions (e.g. `Column(Integer, ForeignKey("users.id"), index=True)`).

### 6.24 SQL-024: Insecure Unencrypted Remote Database Connection URL
- **Default Severity:** `WARNING`
- **Description:** Remote database connection URL targeting external hosts does not specify SSL encryption parameters (`sslmode=require` or `ssl=true`).
- **Remediation:** Append `?sslmode=require` (PostgreSQL) or `?ssl=true` to remote connection strings.

### 6.25 SQL-025: Deprecated `engine.execute()` or `engine.scalar()` Direct Call
- **Default Severity:** `ERROR`
- **Description:** Invoking `engine.execute(...)` or `engine.scalar(...)` directly is removed in SQLAlchemy 2.0.
- **Remediation:** Acquire an explicit connection: `with engine.connect() as conn: result = conn.execute(stmt)`.

### 6.26 SQL-026: `AsyncSession` Instantiated Without Async Context Manager or `await close()`
- **Default Severity:** `WARNING`
- **Description:** `AsyncSession` created in an `async def` function without `async with` or explicit `await session.close()`, causing leaked database connections.
- **Remediation:** Use `async with AsyncSessionLocal() as session:` or ensure `await session.close()` is called in a `finally` block.

### 6.27 SQL-027: Unsafe Concurrent Numeric Balance or Counter Update Without `with_for_update()`
- **Default Severity:** `WARNING`
- **Description:** Querying a record and mutating numeric balances or stock quantities (`balance -= amount`) without row-level locking causes lost-update race conditions.
- **Remediation:** Lock rows using `select(...).with_for_update()` or use atomic SQL increments `update(Account).values(balance=Account.balance - amount)`.

### 6.28 SQL-028: Thread-Local `scoped_session` Used in Async Context
- **Default Severity:** `ERROR`
- **Description:** Using thread-local `scoped_session` in `asyncio` code causes concurrent coroutines to unsafely share session instances.
- **Remediation:** Use `async_scoped_session(..., scopefunc=asyncio.current_task)` or FastAPI per-request dependency injection.

### 6.29 SQL-029: Declarative ORM Model Missing `__tablename__` Definition
- **Default Severity:** `ERROR`
- **Description:** Concrete declarative model class inheriting from `Base` does not declare `__tablename__` or `__table__`.
- **Remediation:** Define `__tablename__ = "table_name"` on the model (or set `__abstract__ = True` for reusable mixins).

### 6.30 SQL-030: Direct DBAPI `raw_connection()` Used Without Cleanup
- **Default Severity:** `WARNING`
- **Description:** Calling `engine.raw_connection()` bypasses connection pool lifecycle management and leaks connections if not closed explicitly.
- **Remediation:** Wrap in `try...finally`: `raw_conn = engine.raw_connection(); try: ... finally: raw_conn.close()`.


