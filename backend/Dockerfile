FROM ollama/ollama:0.40.4

ENV DEBIAN_FRONTEND=noninteractive \
    OLLAMA_HOST=127.0.0.1:11434 \
    OLLAMA_URL=http://127.0.0.1:11434 \
    OLLAMA_MODELS=/opt/ollama/models \
    OLLAMA_NUM_PARALLEL=1 \
    LOCAL_GUARD_MODEL=gemma3:1b \
    PATH=/opt/venv/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /service
RUN set -eu; \
    ollama serve >/tmp/ollama-build.log 2>&1 & server_pid=$!; \
    for attempt in $(seq 1 30); do ollama list >/dev/null 2>&1 && break; sleep 1; done; \
    ollama pull gemma3:1b; \
    kill "$server_pid"; wait "$server_pid" || true

COPY pyproject.toml ./
COPY app ./app
RUN python3 -m venv /opt/venv && pip install --no-cache-dir .

EXPOSE 8000
ENTRYPOINT []
CMD ["/bin/sh", "-c", "ollama serve >/tmp/ollama.log 2>&1 & exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
