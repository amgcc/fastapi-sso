.PHONY: test format types run

test:
	uv run pytest

format:
	uv run black .

types:
	uv run mypy

run:
	uv run uvicorn --app-dir lib main:app --reload --host 0.0.0.0 --port 8000
