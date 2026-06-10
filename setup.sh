#!/bin/bash
# VulnLab Setup Script
# FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY

echo "=================================="
echo "  VulnLab Setup"
echo "  Intentionally Vulnerable App"
echo "=================================="
echo ""

# Check Python version
python3 --version || { echo "Python 3 is required!"; exit 1; }

# Create virtual environment
echo "[*] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "[*] Installing dependencies..."
pip install -r requirements.txt

# Initialize database
echo "[*] Initializing database..."
python3 -c "from app import init_db; init_db()"

echo ""
echo "[+] Setup complete!"
echo "[+] Run with: python3 app.py"
echo "[+] Access at: http://localhost:5000"
echo ""
echo "WARNING: This app is intentionally vulnerable!"
echo "Do NOT deploy on public servers."
