# Build context is the repo root so the shared package can be copied in.
FROM python:3.12-slim

WORKDIR /srv
COPY common /tmp/common
COPY decoys/admin-panel/requirements.txt .
RUN pip install --no-cache-dir /tmp/common -r requirements.txt && rm -rf /tmp/common

COPY decoys/admin-panel/app ./app
EXPOSE 80
# --no-server-header: the app sends its own nginx-style Server header.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80", "--no-server-header", "--no-access-log"]
