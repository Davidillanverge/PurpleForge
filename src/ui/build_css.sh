#!/usr/bin/env bash
# Build the UI stylesheet with the Tailwind v4 standalone CLI (no Node needed).
#   TAILWIND=/path/to/tailwindcss src/ui/build_css.sh
# The compiled src/ui/static/css/app.css is committed so the app runs without a
# build step; rebuild it after changing templates or tailwind/input.css. The
# Docker image rebuilds it from source (Phase 6).
set -euo pipefail
cd "$(dirname "$0")"
TAILWIND="${TAILWIND:-tailwindcss}"
"$TAILWIND" -i tailwind/input.css -o static/css/app.css --minify
echo "built $(pwd)/static/css/app.css ($(wc -c < static/css/app.css) bytes)"
