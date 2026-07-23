#!/bin/bash
# ------------------------------------------------------------------
# Password Manager — quick launch script
# Starts the Flask server on the configured port and opens the browser.
# ------------------------------------------------------------------

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Load .env if it exists
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

PORT="${PM_PORT:-8080}"

echo "=============================================="
echo "  Password Manager"
echo "  Starting on http://localhost:${PORT}"
echo "  Press Ctrl+C to stop"
echo "=============================================="
echo ""

python3 app.py &
APP_PID=$!

sleep 2

if command -v xdg-open &>/dev/null; then
    xdg-open "http://localhost:${PORT}" 2>/dev/null &
elif command -v open &>/dev/null; then
    open "http://localhost:${PORT}" 2>/dev/null &
fi

echo "Server PID: $APP_PID"
echo ""

wait $APP_PID
