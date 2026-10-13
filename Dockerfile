# Multi-stage: dependencies are built in a throwaway stage; the runtime image has no pip, no
# build tools, no shell history, and runs as a fixed non-root UID (Kubernetes runAsNonRoot can
# check a numeric UID, not a name).
FROM python:3.12-slim AS build
WORKDIR /build
COPY app/requirements.txt .
RUN pip install --no-cache-dir --require-hashes --prefix=/install -r requirements.txt

FROM python:3.12-slim
RUN pip uninstall -y pip setuptools wheel 2>/dev/null; \
    rm -rf /root/.cache && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
COPY --from=build /install /usr/local
WORKDIR /app
COPY app/main.py .
USER 10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATABASE_PATH=/tmp/notes.db
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s CMD ["python", "-c", "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/healthz').status != 200)"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
