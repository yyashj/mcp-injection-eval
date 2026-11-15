PY ?= python3
AGENTS ?= naive,guarded,llm
export HOST_UID := $(shell id -u)
export HOST_GID := $(shell id -g)

.PHONY: install test lint eval eval-local docker-build clean

install:
	$(PY) -m pip install -r requirements-dev.txt

test:
	PYTHONPATH=src $(PY) -m pytest -q

lint:
	ruff check src tests

## Reproduce the results table inside Docker (no network inside the eval container)
eval:
	docker compose up --build --abort-on-container-exit --exit-code-from eval eval

## Same thing without Docker
eval-local:
	PYTHONPATH=src $(PY) -m mcpinj.runner --agents $(AGENTS) --out results

docker-build:
	docker compose build

clean:
	rm -rf .pytest_cache **/__pycache__
