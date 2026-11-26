# syntax=docker/dockerfile:1.7
# PurpleForge agent service — multi-stage build.
#
#   docker build -t purpleforge .            # (or: docker compose build)
#
# Stages:
#   css      Tailwind v4 standalone CLI (pinned + checksum-verified) compiles the UI stylesheet
#            from the templates, so the image never depends on the committed app.css being fresh.
#   deps     installs the pinned Python dependencies into /opt/venv (no compiler in the final image).
#   runtime  slim, non-root, read-only-friendly: venv + the harness tree forge needs
#            (scripts/, catalog/, templates/, vendor/, .claude/) + the service (src/).
#
# forge resolves REPO_ROOT from its own __file__, so the harness is NOT pip-installed:
# it runs from /app via PYTHONPATH, exactly like an editable checkout.

ARG PYTHON_IMAGE=python:3.14-slim@sha256:22eafb370920ad8b429e0aec3fff433e0669968519f5d60469d83729c138b28b

# --------------------------------------------------------------------------- css
FROM ${PYTHON_IMAGE} AS css
ARG TARGETARCH
ARG TAILWIND_VERSION=v4.3.5
# sha256 of the official release assets (sha256sums.txt of ${TAILWIND_VERSION}); pinned here,
# not fetched next to the binary, so a tampered release can't vouch for itself.
ARG TAILWIND_SHA256_AMD64=e47695cee3f0d90623a91f3939b08bdee610eb5ad99340adff9d4145b284d6cc
ARG TAILWIND_SHA256_ARM64=ffcd0d21dbd7c605dc12743ff0c0b47debc963c86b399674084c1c8f2c96ecad
WORKDIR /build
RUN python - <<'EOF'
import hashlib, os, stat, urllib.request
arch = os.environ.get("TARGETARCH") or "amd64"
asset, expected = {
    "amd64": ("tailwindcss-linux-x64", os.environ["TAILWIND_SHA256_AMD64"]),
    "arm64": ("tailwindcss-linux-arm64", os.environ["TAILWIND_SHA256_ARM64"]),
}[arch]
url = f"https://github.com/tailwindlabs/tailwindcss/releases/download/{os.environ['TAILWIND_VERSION']}/{asset}"
data = urllib.request.urlopen(url, timeout=120).read()
digest = hashlib.sha256(data).hexdigest()
if digest != expected:
    raise SystemExit(f"tailwind checksum mismatch for {asset}: {digest} != {expected}")
with open("/usr/local/bin/tailwindcss", "wb") as f:
    f.write(data)
os.chmod("/usr/local/bin/tailwindcss", 0o755)
print("tailwind", asset, "verified")
EOF
COPY src/ui/tailwind ./ui/tailwind
COPY src/ui/templates ./ui/templates
COPY src/ui/templating.py ./ui/templating.py
RUN mkdir -p ui/static/css && tailwindcss -i ui/tailwind/input.css -o ui/static/css/app.css --minify

# --------------------------------------------------------------------------- deps
FROM ${PYTHON_IMAGE} AS deps
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /build
COPY pyproject.toml constraints.txt README.md ./
COPY scripts ./scripts
COPY src ./src
# Install the project to pull its pinned deps (constraints = the renderer's locked closure),
# then drop the project itself: the code runs from /app, not from site-packages.
RUN pip install -c constraints.txt ".[app]" && pip uninstall -y purpleforge

# --------------------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE} AS runtime
ARG PF_UID=10001
ARG PF_GID=10001
LABEL org.opencontainers.image.title="purpleforge" \
      org.opencontainers.image.description="PurpleForge agent service: API + UI + agent runtime for isolated purple-team AD labs"

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app/src:/app/scripts \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PF_REPO_ROOT=/app \
    PF_AUTO_MIGRATE=true \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000 \
    UVICORN_WORKERS=1

RUN groupadd --system --gid ${PF_GID} pf \
 && useradd --system --uid ${PF_UID} --gid pf --home-dir /app --shell /usr/sbin/nologin pf

COPY --from=deps /opt/venv /opt/venv
WORKDIR /app
# The harness tree forge and the agents read (read-only at runtime) …
COPY --chown=root:root scripts ./scripts
COPY --chown=root:root catalog ./catalog
COPY --chown=root:root templates ./templates
COPY --chown=root:root vendor ./vendor
COPY --chown=root:root .claude/agents ./.claude/agents
COPY --chown=root:root .claude/skills ./.claude/skills
COPY --chown=root:root specs ./specs
COPY --chown=root:root CLAUDE.md README.md alembic.ini ./
# … the service, with the freshly compiled stylesheet.
COPY --chown=root:root src ./src
COPY --from=css --chown=root:root /build/ui/static/css/app.css ./src/ui/static/css/app.css
# Only these are writable by the service user (mount volumes over them in compose).
RUN mkdir -p /app/generated && chown pf:pf /app/generated /app/specs

USER pf
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=4).status == 200 else 1)"]

# Migrations run in the app lifespan (PF_AUTO_MIGRATE=true, advisory-locked), so N workers
# or replicas can start together. Workers: UVICORN_WORKERS (needs PF_REDIS_URL if > 1).
CMD ["uvicorn", "api.app:create_app", "--factory", "--app-dir", "/app/src", "--proxy-headers"]
