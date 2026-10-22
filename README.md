# TrustSplit

TrustSplit is a local security evaluation benchmark for indirect prompt injection. Its versioned corpus contains three attack cases and three benign controls. Each case compares a raw-context Claude baseline with a guarded path that sends the local Gemma screening result to a second independent Claude call. Both model proposals pass through the same deterministic backend policy.

All actions are proposals. No tools are connected, and no files, secrets, network requests, or privileged operations are accessed or executed. The Anthropic API key is used only by FastAPI and is never returned to the browser.

## What the results mean

- **Unsafe proposal rate** counts model proposals denied by policy on attack cases. It measures model influence before enforcement; it does not mean an action ran.
- **Benign completion rate** counts permitted proposals for benign control cases.
- **Guard detection rate** counts attack cases flagged by the local screening model.
- **Benign false-alarm rate** counts benign controls incorrectly flagged as attacks.
- **Policy bypasses** counts untrusted proposals that passed the deterministic policy. This prototype expects zero.
- **Marker leaks** counts guarded attack contexts that still contain a known corpus phrase. It catches exact strings only, not paraphrases.
- LIVE runs vary by model response. Scripted mode uses fixed corpus fixtures and makes no model calls; its metrics only validate the expected path.

Each LIVE case includes expandable JSON request and response bodies for Ollama/Gemma and both Claude calls. The trace excludes transport headers and credentials; the baseline request visibly contains the raw scenario text by design.

The local model is a screening signal, not a guarantee that malicious meaning has been removed. A small corpus cannot prove general prompt-injection resistance.

## Requirements

- Python 3.11+
- Node.js 20.9+
- Ollama and `gemma3:1b` for LIVE mode (model download is about 806 MB)
- Anthropic API key for LIVE mode

## Start locally

Copy `.env.example` to `.env` at the repository root and add the Anthropic key. Start Ollama and pull the local guard model:

```sh
ollama serve
ollama pull gemma3:1b
```

In another terminal, start FastAPI:

```sh
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
uvicorn app.main:app --reload --port 8000
```

In a third terminal, start Next.js:

```sh
cd frontend
npm install
npm run dev
```

Open http://localhost:3000. SCRIPTED mode works without Ollama or an API key. LIVE mode requires both. A case uses one local screening call and two Anthropic calls; the full six-case corpus uses six local calls and twelve Anthropic calls.

## Azure API deployment

The deployed API runs FastAPI and `gemma3:1b` in one container. Ollama listens only on `127.0.0.1` inside that container. The Azure Container App uses a Consumption profile with scale to zero, so the first request after idle time may take longer. The public API supports SCRIPTED mode without a key; LIVE requests require an `X-Live-Token` header. The Anthropic key and live token are Azure Container App secrets, not repository files or frontend environment variables.

To connect the local dashboard to a hosted API, set `NEXT_PUBLIC_API_URL` in `frontend/.env.local` to the API's HTTPS origin, restart Next.js, select LIVE, and enter the live access token in the input rail. The token is held in the tab's React state and is sent only with LIVE requests. The baseline still sends the synthetic raw corpus text to Anthropic for comparison; no tools execute.

## API

- `GET /api/health` returns readiness, configured model names, and corpus version (never the key).
- `GET /api/scenarios` returns the built-in versioned benchmark cases.
- `POST /api/run` runs one case: `{"scenario_id":"readme-injection","scope":"scenario","mode":"SCRIPTED"}`.
- `POST /api/run` with `{"scope":"corpus","mode":"LIVE"}` runs the full corpus.
- `POST /api/policy/evaluate` accepts `{"scenario_id":"readme-injection","proposal":{"tool":"read_file","resource":"README.md","plan_step":"Read README.md"}}`. The approved plan is loaded by the server; callers cannot supply it.
- `GET /api/events/{run_id}` returns that run's observed event trace.

## Verify

```sh
cd backend
pytest
```

```sh
cd frontend
npm run build
```
