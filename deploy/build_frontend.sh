#!/usr/bin/env bash
# Build the React app into frontend/dist and collect Django's static files.
# Usage: bash deploy/build_frontend.sh
# Set FRONTEND_SRC if portal-refresh is not next to this project.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FRONTEND_SRC="${FRONTEND_SRC:-$PROJECT_DIR/../portal-refresh}"

cd "$FRONTEND_SRC"
npm run build -- --outDir "$PROJECT_DIR/frontend/dist" --emptyOutDir

cd "$PROJECT_DIR"
.venv/bin/python -m whitenoise.compress frontend/dist
.venv/bin/python manage.py collectstatic --noinput
