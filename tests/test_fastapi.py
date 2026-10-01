"""Tests for FastAPI framework analyzer and FAP-001..FAP-008 diagnostic rules."""

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
from qv.frameworks.fastapi import FastApiAnalyzer
from qv.rules.registry import get_rule_definition


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
        for d in (dependencies or ["fastapi"])
    ]
    imps = [
        ImportRecord(
            module_name=imp,
            source_file=root / "app.py",
            line_number=1,
            is_relative=False,
        )
        for imp in (imports or ["fastapi"])
    ]
    return ProjectContext(
        project_root=root,
        project_name="fastapi-app",
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


def test_fastapi_detection():
    analyzer = FastApiAnalyzer()

    # With FastAPI in dependencies
    ctx = make_context([("app.py", "from fastapi import FastAPI\napp = FastAPI()")], ["fastapi"])
    assert analyzer.detect(ctx) is True

    # Without FastAPI
    non_fastapi_ctx = make_context([("app.py", "x = 1")], dependencies=["click"], imports=["click"])
    assert analyzer.detect(non_fastapi_ctx) is False
    assert analyzer.analyze(non_fastapi_ctx) == []


def test_rule_registry_definitions():
    for rule_num in range(1, 25):
        rule_id = f"FAP-{rule_num:03d}"
        rule_def = get_rule_definition(rule_id)
        assert rule_def is not None, f"Rule {rule_id} missing from catalog"
        assert rule_def.id == rule_id


def test_fap_001_blocking_call_and_cpu_hashing():
    code = """
import time
import requests
import subprocess
import bcrypt
from fastapi import FastAPI

app = FastAPI()

@app.get("/slow")
async def slow_route():
    time.sleep(1)
    requests.get("https://api.example.com")
    subprocess.run(["ls"])
    bcrypt.hashpw(b"password", bcrypt.gensalt())
    return {"status": "ok"}

@app.get("/sync-slow")
def sync_slow_route():
    # Sync def routes run in threadpool, so they shouldn't trigger FAP-001
    time.sleep(1)
    return {"status": "ok"}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    blocking_diags = [d for d in diags if d.id == "FAP-001"]
    assert len(blocking_diags) == 4
    assert all(d.severity == Severity.ERROR for d in blocking_diags)

    facts = " ".join([e.fact for d in blocking_diags for e in d.evidence])
    assert "time.sleep" in facts
    assert "requests.get" in facts
    assert "subprocess.run" in facts
    assert "bcrypt.hashpw" in facts


def test_fap_002_blocking_dependency():
    code = """
import time
from fastapi import FastAPI, Depends

app = FastAPI()

def blocking_dep():
    time.sleep(2)
    return True

@app.get("/dep-route")
async def route_with_dep(dep=Depends(blocking_dep)):
    return {"dep": dep}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    dep_diags = [d for d in diags if d.id == "FAP-002"]
    assert len(dep_diags) == 1
    assert dep_diags[0].severity == Severity.WARNING
    assert "blocking_dep" in dep_diags[0].message


def test_fap_003_missing_response_model():
    code = """
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class User(BaseModel):
    id: int

@app.get("/untyped")
async def untyped_route():
    return {"id": 1}

@app.get("/typed-decorator", response_model=User)
async def typed_decorator():
    return {"id": 1}

@app.get("/typed-return")
async def typed_return() -> User:
    return User(id=1)
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    missing_model_diags = [d for d in diags if d.id == "FAP-003"]
    assert len(missing_model_diags) == 1
    assert "untyped_route" in missing_model_diags[0].message


def test_fap_004_insecure_cors_debug_and_oauth2():
    code = """
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer

app = FastAPI(debug=True)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="http://api.example.com/token")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    sec_diags = [d for d in diags if d.id == "FAP-004"]
    assert len(sec_diags) == 3
    err_cors = [d for d in sec_diags if "CORS" in d.title]
    warn_debug = [d for d in sec_diags if "debug mode" in d.title]
    err_oauth2 = [d for d in sec_diags if "OAuth2" in d.title]
    assert len(err_cors) == 1
    assert len(warn_debug) == 1
    assert len(err_oauth2) == 1


def test_fap_005_missing_client_timeout():
    code = """
import httpx
from fastapi import FastAPI

app = FastAPI()

@app.get("/external")
async def external():
    async with httpx.AsyncClient() as client:
        resp = await client.get("https://example.com")
    return resp.json()
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    timeout_diags = [d for d in diags if d.id == "FAP-005"]
    assert len(timeout_diags) == 1
    assert timeout_diags[0].severity == Severity.WARNING
    assert "httpx.AsyncClient" in timeout_diags[0].message


def test_fap_006_path_parameter_mismatch():
    code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/users/{user_id}/orders/{order_id}")
async def get_user_order(uid: int, order_id: int) -> dict:
    return {"user": uid, "order": order_id}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    param_diags = [d for d in diags if d.id == "FAP-006"]
    assert len(param_diags) == 1
    assert param_diags[0].severity == Severity.ERROR
    assert "user_id" in param_diags[0].message


def test_fap_007_unsafe_yield_dependency():
    code = """
from fastapi import FastAPI

app = FastAPI()

def unsafe_db():
    db = {"connected": True}
    yield db
    db["connected"] = False

def safe_db():
    db = {"connected": True}
    try:
        yield db
    finally:
        db["connected"] = False
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    yield_diags = [d for d in diags if d.id == "FAP-007"]
    assert len(yield_diags) == 1
    assert yield_diags[0].severity == Severity.WARNING
    assert "unsafe_db" in yield_diags[0].message


def test_fap_008_deprecated_lifecycle_hook():
    code = """
from fastapi import FastAPI

app = FastAPI()

@app.on_event("startup")
async def startup_hook():
    pass
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    lifecycle_diags = [d for d in diags if d.id == "FAP-008"]
    assert len(lifecycle_diags) == 1
    assert lifecycle_diags[0].severity == Severity.WARNING
    assert "startup" in lifecycle_diags[0].title


def test_fap_009_untyped_request_body():
    code = """
from typing import Any
from fastapi import FastAPI

app = FastAPI()

@app.post("/items")
def create_item(payload: dict) -> dict:
    return payload

@app.put("/users")
def update_user(data: Any) -> dict:
    return {}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    untyped_diags = [d for d in diags if d.id == "FAP-009"]
    assert len(untyped_diags) == 2
    assert all(d.severity == Severity.WARNING for d in untyped_diags)


def test_fap_010_duplicate_routes():
    code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
def get_users_v1():
    return []

@app.get("/users")
def get_users_v2():
    return []
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    dup_diags = [d for d in diags if d.id == "FAP-010"]
    assert len(dup_diags) == 1
    assert dup_diags[0].severity == Severity.ERROR
    assert "GET /users" in dup_diags[0].message


def test_fap_011_mutable_defaults():
    code = """
from fastapi import FastAPI, Query

app = FastAPI()

@app.get("/search")
def search(tags: list = Query([]), options: dict = {}):
    return {"tags": tags}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    mutable_diags = [d for d in diags if d.id == "FAP-011"]
    assert len(mutable_diags) == 2
    assert all(d.severity == Severity.WARNING for d in mutable_diags)


def test_fap_012_exception_handler_signature():
    code = """
from fastapi import FastAPI

app = FastAPI()

@app.exception_handler(ValueError)
def bad_handler(exc: ValueError):
    # Missing request parameter!
    return None

@app.exception_handler(KeyError)
def good_handler(request, exc: KeyError):
    return None
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    exc_diags = [d for d in diags if d.id == "FAP-012"]
    assert len(exc_diags) == 1
    assert exc_diags[0].severity == Severity.ERROR
    assert "bad_handler" in exc_diags[0].message


def test_fap_013_untracked_create_task():
    code = """
import asyncio
from fastapi import FastAPI

app = FastAPI()

async def bg_job():
    pass

@app.post("/trigger")
async def trigger() -> dict:
    asyncio.create_task(bg_job())
    return {"status": "started"}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    task_diags = [d for d in diags if d.id == "FAP-013"]
    assert len(task_diags) == 1
    assert task_diags[0].severity == Severity.WARNING
    assert "asyncio.create_task" in task_diags[0].evidence[0].fact


def test_fap_014_path_traversal_fileresponse():
    code = """
from fastapi import FastAPI
from fastapi.responses import FileResponse

app = FastAPI()

@app.get("/download/{filename}")
def download(filename: str):
    return FileResponse(filename)
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    traversal_diags = [d for d in diags if d.id == "FAP-014"]
    assert len(traversal_diags) == 1
    assert traversal_diags[0].severity == Severity.WARNING
    assert "filename" in traversal_diags[0].message


def test_fap_015_blocking_file_io():
    code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/read")
async def read_file():
    with open("data.txt") as f:
        return f.read()
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    file_diags = [d for d in diags if d.id == "FAP-015"]
    assert len(file_diags) == 1
    assert file_diags[0].severity == Severity.ERROR
    assert "open()" in file_diags[0].message


def test_fap_016_sensitive_field_exposure():
    code = """
from pydantic import BaseModel, Field

class UserSchema(BaseModel):
    id: int
    password: str
    secret_key: str = Field(exclude=True)
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    sec_diags = [d for d in diags if d.id == "FAP-016"]
    assert len(sec_diags) == 1
    assert sec_diags[0].severity == Severity.ERROR
    assert "password" in sec_diags[0].message


def test_fap_017_status_code_mutation():
    code = """
from fastapi import FastAPI

app = FastAPI()

@app.post("/create")
def create_item():
    return {"id": 1}

@app.delete("/delete")
def delete_item():
    return {}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    status_diags = [d for d in diags if d.id == "FAP-017"]
    assert len(status_diags) == 2
    assert all(d.severity == Severity.WARNING for d in status_diags)


def test_fap_018_global_state_mutation():
    code = """
from fastapi import FastAPI

app = FastAPI()
CACHE = {}

@app.post("/set")
def set_cache(key: str, val: str):
    CACHE[key] = val
    return {"ok": True}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    global_diags = [d for d in diags if d.id == "FAP-018"]
    assert len(global_diags) == 1
    assert global_diags[0].severity == Severity.ERROR
    assert "CACHE" in global_diags[0].message


def test_fap_019_insecure_cookies():
    code = """
from fastapi import FastAPI, Response

app = FastAPI()

@app.post("/login")
def login(response: Response):
    response.set_cookie(key="session", value="123", httponly=False)
    return {}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    cookie_diags = [d for d in diags if d.id == "FAP-019"]
    assert len(cookie_diags) == 1
    assert cookie_diags[0].severity == Severity.ERROR


def test_fap_020_open_redirect():
    code = """
from fastapi import FastAPI
from fastapi.responses import RedirectResponse

app = FastAPI()

@app.get("/redirect")
def do_redirect(target_url: str):
    return RedirectResponse(target_url)
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    redir_diags = [d for d in diags if d.id == "FAP-020"]
    assert len(redir_diags) == 1
    assert redir_diags[0].severity == Severity.WARNING
    assert "target_url" in redir_diags[0].message


def test_fap_021_router_missing_tags_prefix():
    code = """
from fastapi import FastAPI, APIRouter

app = FastAPI()
router = APIRouter()

app.include_router(router)
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    router_diags = [d for d in diags if d.id == "FAP-021"]
    assert len(router_diags) == 1
    assert router_diags[0].severity == Severity.WARNING


def test_fap_022_websocket_missing_accept():
    code = """
from fastapi import FastAPI, WebSocket

app = FastAPI()

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    data = await websocket.receive_text()
    await websocket.send_text(f"Echo: {data}")
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    ws_diags = [d for d in diags if d.id == "FAP-022"]
    assert len(ws_diags) == 1
    assert ws_diags[0].severity == Severity.ERROR
    assert "websocket.accept()" in ws_diags[0].message


def test_fap_023_deprecated_class_config():
    code = """
from pydantic import BaseModel

class LegacyModel(BaseModel):
    id: int

    class Config:
        from_attributes = True
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    config_diags = [d for d in diags if d.id == "FAP-023"]
    assert len(config_diags) == 1
    assert config_diags[0].severity == Severity.WARNING


def test_fap_024_duplicate_depends():
    code = """
from fastapi import FastAPI, Depends

app = FastAPI()

def get_db():
    return {}

@app.get("/items")
def get_items(db1=Depends(get_db), db2=Depends(get_db)):
    return {}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    dup_dep_diags = [d for d in diags if d.id == "FAP-024"]
    assert len(dup_dep_diags) == 1
    assert dup_dep_diags[0].severity == Severity.WARNING
    assert "get_db" in dup_dep_diags[0].message


def test_fap_025_returned_httpexception():
    code = """
from fastapi import FastAPI, HTTPException

app = FastAPI()

@app.get("/items/{item_id}")
def get_item(item_id: int):
    if item_id < 0:
        return HTTPException(status_code=404, detail="Item not found")
    return {"id": item_id}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    ret_exc_diags = [d for d in diags if d.id == "FAP-025"]
    assert len(ret_exc_diags) == 1
    assert ret_exc_diags[0].severity == Severity.ERROR
    assert "HTTPException" in ret_exc_diags[0].message


def test_fap_026_deprecated_pydantic_validator():
    code = """
from pydantic import BaseModel, validator

class User(BaseModel):
    name: str

    @validator("name")
    def name_must_contain_space(cls, v):
        return v
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    val_diags = [d for d in diags if d.id == "FAP-026"]
    assert len(val_diags) == 1
    assert val_diags[0].severity == Severity.WARNING
    assert "validator" in val_diags[0].message


def test_fap_027_missing_dependency_type_annotation():
    code = """
from fastapi import FastAPI, Depends

app = FastAPI()

def get_db():
    return {}

@app.get("/users")
def get_users(db=Depends(get_db)):
    return []
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    type_diags = [d for d in diags if d.id == "FAP-027"]
    assert len(type_diags) == 1
    assert type_diags[0].severity == Severity.WARNING
    assert "type annotation" in type_diags[0].message


def test_fap_028_raw_json_loads_on_request_body():
    code = """
import json
from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/webhook")
async def webhook(request: Request):
    data = json.loads(await request.body())
    return data
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    json_diags = [d for d in diags if d.id == "FAP-028"]
    assert len(json_diags) == 1
    assert json_diags[0].severity == Severity.WARNING
    assert "json.loads" in json_diags[0].message


def test_fap_029_streaming_response_missing_media_type():
    code = """
from fastapi import FastAPI
from fastapi.responses import StreamingResponse

app = FastAPI()

def fake_stream():
    yield b"data"

@app.get("/stream")
def stream_endpoint():
    return StreamingResponse(fake_stream())
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    stream_diags = [d for d in diags if d.id == "FAP-029"]
    assert len(stream_diags) == 1
    assert stream_diags[0].severity == Severity.WARNING
    assert "media_type" in stream_diags[0].message


def test_fap_030_missing_route_summary_or_docstring():
    code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/undocumented")
def undocumented_route():
    return {"status": "ok"}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    doc_diags = [d for d in diags if d.id == "FAP-030"]
    assert len(doc_diags) == 1
    assert doc_diags[0].severity == Severity.WARNING
    assert "docstring" in doc_diags[0].message


def test_fap_031_prefer_annotated_syntax():
    code = """
from fastapi import FastAPI, Depends

app = FastAPI()

def get_db():
    return {}

@app.get("/items")
def list_items(db: dict = Depends(get_db)):
    \"\"\"List all items.\"\"\"
    return []
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    annotated_diags = [d for d in diags if d.id == "FAP-031"]
    assert len(annotated_diags) == 1
    assert annotated_diags[0].severity == Severity.INFO
    assert "Annotated" in annotated_diags[0].message


def test_fap_032_redundant_jsonable_encoder():
    code = """
from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel

app = FastAPI()

class UserOut(BaseModel):
    id: int

@app.get("/user", response_model=UserOut)
def get_user():
    \"\"\"Get user.\"\"\"
    return jsonable_encoder({"id": 1})
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    enc_diags = [d for d in diags if d.id == "FAP-032"]
    assert len(enc_diags) == 1
    assert enc_diags[0].severity == Severity.WARNING
    assert "jsonable_encoder" in enc_diags[0].message


def test_fap_033_missing_from_attributes_in_response_schema():
    code = """
from pydantic import BaseModel

class UserResponse(BaseModel):
    id: int
    username: str
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    orm_diags = [d for d in diags if d.id == "FAP-033"]
    assert len(orm_diags) == 1
    assert orm_diags[0].severity == Severity.WARNING
    assert "from_attributes=True" in orm_diags[0].message


def test_fap_034_missing_await_on_request_json():
    code = """
from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/submit")
async def submit(request: Request):
    \"\"\"Submit handler.\"\"\"
    data = request.json()
    return {"status": "received"}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    await_diags = [d for d in diags if d.id == "FAP-034"]
    assert len(await_diags) == 1
    assert await_diags[0].severity == Severity.ERROR
    assert "request.json()" in await_diags[0].message


def test_fap_035_raw_exception_raised():
    code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/items/{item_id}")
def get_item(item_id: int):
    \"\"\"Get single item.\"\"\"
    if item_id < 0:
        raise ValueError("Invalid item ID")
    return {"id": item_id}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    exc_diags = [d for d in diags if d.id == "FAP-035"]
    assert len(exc_diags) == 1
    assert exc_diags[0].severity == Severity.WARNING
    assert "ValueError" in exc_diags[0].message


def test_fap_036_mutating_app_state():
    code = """
from fastapi import FastAPI, Request

app = FastAPI()

@app.get("/count")
def increment_counter(request: Request):
    \"\"\"Increment counter.\"\"\"
    request.app.state.counter += 1
    return {"counter": request.app.state.counter}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    state_diags = [d for d in diags if d.id == "FAP-036"]
    assert len(state_diags) == 1
    assert state_diags[0].severity == Severity.WARNING
    assert "app.state" in state_diags[0].message


def test_fap_037_security_scopes_with_depends():
    code = """
from fastapi import FastAPI, Depends
from fastapi.security import SecurityScopes

app = FastAPI()

def verify_token(scopes: SecurityScopes = Depends()):
    return scopes

@app.get("/protected")
def protected_route(scopes: SecurityScopes = Depends(verify_token)):
    \"\"\"Protected route.\"\"\"
    return {"ok": True}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    scope_diags = [d for d in diags if d.id == "FAP-037"]
    assert len(scope_diags) >= 1
    assert scope_diags[0].severity == Severity.WARNING
    assert "SecurityScopes" in scope_diags[0].message


def test_fap_038_hardcoded_status_code_integer():
    code = """
from fastapi import FastAPI

app = FastAPI()

@app.post("/create", status_code=201)
def create_item():
    \"\"\"Create an item.\"\"\"
    return {"created": True}
"""
    ctx = make_context([("main.py", code)])
    analyzer = FastApiAnalyzer()
    diags = analyzer.analyze(ctx)

    status_diags = [d for d in diags if d.id == "FAP-038"]
    assert len(status_diags) == 1
    assert status_diags[0].severity == Severity.INFO
    assert "status_code=201" in status_diags[0].message
