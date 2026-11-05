# Build context is the repo root so the shared package can be copied in.
FROM python:3.12-slim

WORKDIR /srv
COPY common /tmp/common
COPY decoys/s3/requirements.txt .
RUN pip install --no-cache-dir /tmp/common -r requirements.txt && rm -rf /tmp/common

COPY decoys/s3/app ./app
EXPOSE 9000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000", "--no-access-log"]
