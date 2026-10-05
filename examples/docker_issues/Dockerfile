FROM python:latest

WORKDIR /app

COPY .env /app/.env
COPY . .

RUN pip install -r requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
