import time

import httpx
import requests
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer

# FAP-004: debug=True
app = FastAPI(debug=True)

# FAP-004: Insecure plaintext HTTP OAuth2 token URL
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="http://auth.example.com/token")

# FAP-004: Insecure CORS wildcard with allow_credentials=True
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# FAP-007: Unsafe yield dependency without try...finally
def get_db_session():
    db = {"connected": True}
    yield db
    # If request fails, this close() is never reached
    db["connected"] = False


def blocking_sync_dependency():
    time.sleep(1)
    return {"user": "alice"}


# FAP-008: Deprecated on_event startup hook
@app.on_event("startup")
async def startup_event():
    pass


# FAP-001: Blocking calls in async route
# FAP-002: Dependent on blocking_sync_dependency
# FAP-003: Missing response_model / return annotation
# FAP-006: Route template mismatch ({item_id} missing in function arguments)
@app.get("/items/{item_id}")
async def get_items(
    auth=Depends(blocking_sync_dependency),  # noqa: B008
    db=Depends(get_db_session),  # noqa: B008
):
    # Blocking calls in async def
    time.sleep(2)
    requests.get("https://api.example.com/data")

    # FAP-005: Missing timeout on HTTP client
    async with httpx.AsyncClient() as client:
        resp = await client.get("https://httpbin.org/get")

    return {"auth": auth, "data": resp.status_code}
