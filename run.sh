#!/usr/bin/env bash
set -e

echo "[*] Setting up The Silent Conch: The Eleventh Seal..."
python -m pip install -r requirements.txt
python scripts/generate_pcap.py
echo "[*] Launching challenge server..."
python start_server.py
