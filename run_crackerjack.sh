#!/usr/bin/env bash
set -e

REQUIRED_PACKAGES="git screen python3-venv python3-pip sqlite3"

echo "[*] Checking required packages..."
sudo apt update
sudo apt install -y $REQUIRED_PACKAGES

VENV_DIR="venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv $VENV_DIR
fi

source $VENV_DIR/bin/activate

echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# ────────────────────────────────────────────────
# Database migrations
# ────────────────────────────────────────────────
echo "[*] Applying database migrations..."
flask db init || true   # ignore if already initialized
flask db migrate
flask db upgrade

# ────────────────────────────────────────────────
# Run Flask app
# ────────────────────────────────────────────────
echo "[*] Starting Crackerjack Flask app..."
export FLASK_ENV=development
export FLASK_APP=app

flask run
