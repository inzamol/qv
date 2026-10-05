from fastapi import FastAPI

app = FastAPI(title="Docker Example App")


@app.get("/")
def read_root():
    return {"status": "ok"}
