# PurpleForge — development and artifact-packaging targets
# Requires: GNU make, Python 3.11+, zip
#
# Quick-start:
#   make test        — run the test suite
#   make artifact    — build a Zenodo-ready zip in dist/
#   make all         — full quality-gate pipeline + artifact

PYTHON   ?= python3
PIP      ?= $(PYTHON) -m pip
PYTEST   ?= $(PYTHON) -m pytest
RUFF     ?= $(PYTHON) -m ruff
BANDIT   ?= $(PYTHON) -m bandit
PIPAUDIT ?= $(PYTHON) -m pip_audit
CYCLONE  ?= cyclonedx-py
ZIP      ?= zip

DESELECT := --deselect tests/test_scenarios.py::test_web_target_requires_base_url

DIST_DIR     := dist/artifact
DIST_ZIP     := dist/purpleforge_artifact.zip

.PHONY: all test lint security sbom artifact clean help

all: test lint security sbom artifact

# ── Test ──────────────────────────────────────────────────────────────────────
test:
	$(PYTEST) tests/ $(DESELECT) -q

# ── Lint ──────────────────────────────────────────────────────────────────────
lint:
	$(RUFF) check purpleforge/ tests/ --exit-zero

# ── Security ──────────────────────────────────────────────────────────────────
security:
	$(BANDIT) -r purpleforge/ -ll
	@$(PIP) freeze --exclude-editable > /tmp/audit-requirements.txt
	$(PIPAUDIT) --strict -r /tmp/audit-requirements.txt

# ── SBOM ──────────────────────────────────────────────────────────────────────
sbom:
	$(CYCLONE) environment -o sbom.json || \
	$(CYCLONE) requirements requirements.txt -o sbom.json || \
	($(PIP) freeze > /tmp/reqs_for_sbom.txt && $(CYCLONE) requirements /tmp/reqs_for_sbom.txt -o sbom.json)
	@echo "SBOM written to sbom.json"

# ── Artifact (Zenodo-ready zip) ───────────────────────────────────────────────
artifact: _clean_dist _copy_sources _gen_lock _write_metadata _zip_artifact

_clean_dist:
	rm -rf $(DIST_DIR) $(DIST_ZIP)
	mkdir -p $(DIST_DIR)

_copy_sources:
	cp -r purpleforge/         $(DIST_DIR)/purpleforge/
	cp -r tests/               $(DIST_DIR)/tests/
	cp -r examples/            $(DIST_DIR)/examples/
	cp    pyproject.toml       $(DIST_DIR)/pyproject.toml
	cp    README.md            $(DIST_DIR)/README.md
	cp    LICENSE              $(DIST_DIR)/LICENSE
	cp    REPRODUCIBILITY.md   $(DIST_DIR)/REPRODUCIBILITY.md
	cp    CITATION.cff         $(DIST_DIR)/CITATION.cff
	mkdir -p $(DIST_DIR)/.github/workflows
	cp    .github/workflows/ci.yml $(DIST_DIR)/.github/workflows/ci.yml

_gen_lock:
	$(PIP) freeze > $(DIST_DIR)/requirements.lock
	@echo "requirements.lock generated"

_write_metadata:
	@echo "Artifact contents:"
	@find $(DIST_DIR) -type f | sort

_zip_artifact:
	cd dist && $(ZIP) -r purpleforge_artifact.zip artifact/
	@echo ""
	@echo "Artifact zip: $(DIST_ZIP)"
	$(PYTHON) scripts/sha256_print.py $(DIST_ZIP)

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
	rm -rf dist/ sbom.json .coverage htmlcov/ .pytest_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# ── Help ──────────────────────────────────────────────────────────────────────
help:
	@echo "PurpleForge Makefile"
	@echo ""
	@echo "  make test      — run pytest suite (370 tests)"
	@echo "  make lint      — ruff check (exit-zero, non-blocking)"
	@echo "  make security  — bandit + pip-audit"
	@echo "  make sbom      — generate CycloneDX SBOM to sbom.json"
	@echo "  make artifact  — build Zenodo-ready zip to dist/purpleforge_artifact.zip"
	@echo "  make all       — test + lint + security + sbom + artifact"
	@echo "  make clean     — remove build/cache artefacts"
