# Build context is the repo root so the shared package can be copied in.
FROM python:3.12-slim

WORKDIR /srv
COPY common /tmp/common
COPY decoys/ssh/requirements.txt .
RUN pip install --no-cache-dir /tmp/common -r requirements.txt && rm -rf /tmp/common

COPY decoys/ssh/app ./app
EXPOSE 22
CMD ["python", "-m", "app.server"]
