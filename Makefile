.PHONY: install test lint check demo clean

install:
	python -m venv .venv
	. .venv/bin/activate && pip install -e '.[dev]'

test:
	. .venv/bin/activate && pytest -q

lint:
	. .venv/bin/activate && ruff check src tests
	. .venv/bin/activate && ruff format --check src tests

check: lint test

demo:
	. .venv/bin/activate && adversaryflow generate --request examples/apt29_request.json --output reports/apt29_scenario.md --demo

clean:
	rm -rf .pytest_cache .ruff_cache reports src/adversaryflow.egg-info build dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
