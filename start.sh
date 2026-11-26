#!/usr/bin/env bash
# One-command start for Mini Guardrail on macOS / Linux (also works in Git Bash on Windows).
#
#   ./start.sh                                   setup + tests + server + browser
#   ./start.sh --port 8080 --skip-tests --no-browser
#
# Steps: find Python 3.10+, create .venv (first run), install dependencies
# (only when pyproject.toml changed), run tests, start the server.
set -euo pipefail
cd "$(dirname "$0")"

PORT=8000
RUN_TESTS=1
OPEN_BROWSER=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)       PORT="$2"; shift 2 ;;
    --skip-tests) RUN_TESTS=0; shift ;;
    --no-browser) OPEN_BROWSER=0; shift ;;
    -h|--help)    sed -n '2,9p' "$0"; exit 0 ;;
    *)            echo "Unknown option: $1 (see ./start.sh --help)"; exit 1 ;;
  esac
done

step() { printf '\n\033[36m==> %s\033[0m\n' "$1"; }
fail() { printf '\n\033[31mERROR: %s\033[0m\n' "$1"; exit 1; }

find_python() {
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 &&
       "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
      echo "$c"; return 0
    fi
  done
  return 1
}

if [[ -x .venv/bin/python ]]; then
  VENV_PY=.venv/bin/python
elif [[ -x .venv/Scripts/python.exe ]]; then   # Git Bash on Windows
  VENV_PY=.venv/Scripts/python.exe
else
  step "Creating virtual environment (.venv)"
  PY=$(find_python) || fail "Python 3.10 or newer was not found. Install it from https://www.python.org/downloads/ and run this again."
  "$PY" -m venv .venv || fail "Could not create the virtual environment (on Debian/Ubuntu: sudo apt install python3-venv)."
  if [[ -x .venv/bin/python ]]; then VENV_PY=.venv/bin/python; else VENV_PY=.venv/Scripts/python.exe; fi
fi

HASH_FILE=.venv/.installed-hash
CURRENT_HASH=$("$VENV_PY" -c "import hashlib; print(hashlib.sha256(open('pyproject.toml','rb').read()).hexdigest().upper())")
INSTALLED_HASH=$(cat "$HASH_FILE" 2>/dev/null | tr -d '[:space:]' || true)

if [[ "$CURRENT_HASH" != "$INSTALLED_HASH" ]]; then
  step "Installing dependencies (first run can take a minute)"
  "$VENV_PY" -m pip install --disable-pip-version-check -q --upgrade pip
  "$VENV_PY" -m pip install --disable-pip-version-check -q -e ".[dev]" || fail "Dependency installation failed. See the messages above."
  echo "$CURRENT_HASH" > "$HASH_FILE"
else
  step "Dependencies already up to date"
fi

if [[ $RUN_TESTS -eq 1 ]]; then
  step "Running tests"
  "$VENV_PY" -m pytest -q -p no:warnings || fail "Tests failed. Fix them, or start anyway with: ./start.sh --skip-tests"
fi

if "$VENV_PY" -c "import socket,sys; s=socket.socket(); s.settimeout(0.5); sys.exit(0 if s.connect_ex(('127.0.0.1', int(sys.argv[1]))) == 0 else 1)" "$PORT"; then
  fail "Port $PORT is already in use. Try another one: ./start.sh --port 8080"
fi

printf '\n\033[32m  Mini Guardrail is starting\033[0m\n'
echo "  Playground : http://127.0.0.1:$PORT"
echo "  API docs   : http://127.0.0.1:$PORT/docs"
echo "  Press Ctrl+C to stop."
echo

SERVE_ARGS=(-m guardrail serve --port "$PORT")
[[ $OPEN_BROWSER -eq 1 ]] && SERVE_ARGS+=(--open)
exec "$VENV_PY" "${SERVE_ARGS[@]}"
