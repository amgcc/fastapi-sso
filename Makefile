.PHONY: test format run

test:
	uv run pytest

format:
	uv run black .

run:
	uv run uvicorn --app-dir lib main:app --reload --host 0.0.0.0 --port 8000
