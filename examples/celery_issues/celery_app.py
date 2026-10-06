from celery import Celery

app = Celery("example_tasks", broker="redis://localhost:6379/0")

# CEL-001: Insecure pickle serializer configuration
app.conf.update(
    task_serializer="pickle",
    result_serializer="pickle",
    accept_content=["pickle"],
)
