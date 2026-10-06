import time

from .celery_app import app


# CEL-002: Missing time_limit / soft_time_limit
# CEL-003: Unbounded retries (max_retries=None)
# CEL-004: Synchronous blocking time.sleep() inside async/task context
@app.task(bind=True, max_retries=None)
def process_data(self, record_id: int):
    # CEL-004: Blocking call
    time.sleep(5)
    return {"status": "ok", "id": record_id}
