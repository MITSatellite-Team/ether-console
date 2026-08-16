# ether-console

Desktop ground console for ETHER. It decodes the payload's multi-rate telemetry stream over USB serial, displays it live, and logs it.

## Setup

CPython 3.13, pinned in `.python-version`.

**With uv** — downloads 3.13 automatically if you don't have it.

```
uv venv
uv pip install -r requirements.txt
```

**Without uv** — install [CPython 3.13](https://www.python.org/downloads/) first, then:

```
py -3.13 -m venv .venv
.venv\Scripts\Activate.ps1          # PowerShell (use .venv/Scripts/activate in bash)
pip install -r requirements.txt
```

Then point your editor's interpreter at `.venv\Scripts\python.exe`.
