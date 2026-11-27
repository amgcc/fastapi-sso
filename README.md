# FastAPI SSO Lab

Microsoft Entra OIDC sign-in with FastAPI, signed session cookies, and SQLite session storage.

## Setup

Install [uv](https://docs.astral.sh/uv/), then from the project root:

```bash
uv sync --group dev
cp .env.example .env   # if present; otherwise create .env with required variables
uv run pre-commit install
```

Required environment variables: `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `SESSION_SECRET`.

## Run

```bash
uv run uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Formatting

Black runs on commit via pre-commit. To format or check manually:

```bash
uv run black .
uv run pre-commit run --all-files
```