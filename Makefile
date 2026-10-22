# ==============================================================================
# JANUS-Evidence Makefile
# Supports both local macOS (darwin/arm64) execution and Docker (linux/arm64)
# ==============================================================================

PYTHON ?= python3
VENV ?= venv
BIN := $(VENV)/bin
DOCKER_IMAGE ?= janus-evidence:latest
DOCKER_PLATFORM ?= linux/arm64

.PHONY: help install test lint docker-build clean

help:
	@echo "JANUS-Evidence Build & Test Automation (ARM64 Compatible)"
	@echo "---------------------------------------------------------"
	@echo "  make install       Create local Python venv and install requirements.txt"
	@echo "  make test          Run pytest suite inside local venv"
	@echo "  make lint          Check Python syntax and formatting"
	@echo "  make docker-build  Build ARM64-compatible Docker image"
	@echo "  make clean         Remove Python caches and build artifacts"

install:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip setuptools wheel
	$(BIN)/pip install -r requirements.txt

test:
	@if [ -d "$(VENV)" ]; then \
		$(BIN)/pytest -v tests/; \
	else \
		$(PYTHON) -m pytest -v tests/; \
	fi

lint:
	@if [ -d "$(VENV)" ]; then \
		$(BIN)/python -m compileall -q core/ experiments/ scripts/ tests/; \
	else \
		$(PYTHON) -m compileall -q core/ experiments/ scripts/ tests/; \
	fi

docker-build:
	docker build --platform $(DOCKER_PLATFORM) -t $(DOCKER_IMAGE) .

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	rm -rf out/ cache/ broadcast/

