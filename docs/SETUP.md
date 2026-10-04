# Setup

## Prerequisites

- Python 3.11 or newer (developed on 3.14)
- Node.js 20 or newer
- Optional: [Ollama](https://ollama.com) for the optional intelligence layer. The platform is fully
  functional without it.

No internet access is required at runtime. Dependencies are installed once, then the system runs
entirely on the local machine with the network egress guard active.

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
cd frontend
npm install
cd ..
```

## Run

Terminal 1 — backend:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

On first start the backend:

1. creates the operational database and three separate ledger node databases,
2. issues ML-DSA-65 and ML-KEM-768 keys for each ledger node,
3. writes the shared genesis anchor to every node,
4. seeds the synthetic identities, devices and documents.

Terminal 2 — frontend:

```powershell
cd frontend
npm run dev
```

Open `http://127.0.0.1:5173`.

## Why the backend is started with `--app-dir backend`

`app.main:app` lives inside `backend/`. Using `--app-dir` keeps the package importable without
installing it and without polluting the repository root. `cd backend` and running `pytest ..\tests`
works for the same reason.

## Configuration

Every setting has a working default. Overrides are environment variables:

| Variable | Default | Effect |
|---|---|---|
| `SENTINEL_AIR_GAPPED` | `1` | Runtime egress guard blocks all non-loopback sockets |
| `SENTINEL_WM_STRENGTH` | `0.03` | Watermark embedding amplitude in 8×8 DCT units |
| `SENTINEL_WM_CARRIERS` | `512` | Independent carriers per payload bit |
| `SENTINEL_OLLAMA_MODEL` | `llama3.1:8b` | Local model used for optional summaries |
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Local model endpoint |
| `FORGE_MASTER_PASSPHRASE` | unset | Passphrase protecting the local key vault |

Do not change the watermark parameters without re-running the calibration:

```powershell
.\.venv\Scripts\python.exe scripts\calibrate_watermark.py
```

## Key vault

Private keys live in `keys/identities.json`, each one encrypted with AES-256-GCM under a key derived
by scrypt. The key-encryption key comes from `FORGE_MASTER_PASSPHRASE` when set; otherwise a
generated file `data/master_secret.bin` is used.

> The generated-file path is a **development convenience**. It offers no protection against an
> attacker who already has the machine. Production replaces this with hardware-backed, non-exportable
> keys — see `docs/PRODUCTION_GAPS.md`.

## Optional: local AI

```powershell
ollama serve
ollama pull llama3.1:8b
```

Without it the intelligence screen reports `AI SERVICE OFFLINE` and every deterministic security
function continues to operate unchanged.

## Verification

```powershell
# 21-step forensic demonstration
.\.venv\Scripts\python.exe scripts\demo_end_to_end.py

# HTTP-level verification against the real app
.\.venv\Scripts\python.exe scripts\api_smoke.py

# import and primitive smoke test
.\.venv\Scripts\python.exe scripts\smoke_test.py

# automated suite
cd backend
..\.venv\Scripts\python.exe -m pytest ..\tests
```

## Resetting state

All runtime state is regenerable. Stop the backend and delete these directories:

```powershell
Remove-Item -Recurse -Force data, ledger, evidence, keys
```

The next start recreates them and re-seeds the synthetic environment.

> Delete `keys/` only when you intend to invalidate every existing identity. Deleting `ledger/`
> discards history, which in a real deployment would be evidence destruction — the reason the ledger
> is append-only and the audit chain is separately hash-anchored.

## Troubleshooting

**Backend reports `no such table`** — the process was started from the wrong directory, so
`--app-dir backend` did not apply. Start it from the repository root.

**Watermark recovery returns `WATERMARK NOT RECOVERED`** on an untouched copy — check that the
submitted file is a PDF produced by this system, and that `data/` was not modified between
decryption and analysis. Run `scripts/calibrate_watermark.py` to confirm the parameters still match
the documented figures.

**`OFFLINE_SECURITY_POLICY_VIOLATION` in the log** — something attempted a non-loopback connection
while air-gapped mode was active. That is the guard working: the attempt was refused, not completed.

**Ledger reports `CONSISTENCY FAILURE`** — a node diverged, most often because the security
laboratory exercised a tamper scenario. Re-run `scripts/demo_end_to_end.py`, which restores the
original value and records the attempt.

**Port already in use** — change `--port` on the backend and update the proxy target in
`frontend/vite.config.ts`.
