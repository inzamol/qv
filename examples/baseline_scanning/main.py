# Legacy file with known DEP-002 issue that is recorded in .qv-baseline.json
import httpx


def fetch_data():
    response = httpx.get("https://api.example.com")
    return response.status_code
