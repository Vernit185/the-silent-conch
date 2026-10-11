"""
Launcher for The Silent Conch challenge server.
"""

import os
import sys
import uvicorn

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import SERVER_HOST, SERVER_PORT, PCAP_PATH
from scripts.generate_pcap import generate_telemetry_pcap

def main():
    # Ensure PCAP artifact exists before starting server
    if not os.path.exists(PCAP_PATH):
        print("[*] Generating telemetry PCAP artifact...")
        generate_telemetry_pcap()

    print(f"[*] Starting Kurukshetra Relay Gateway on http://{SERVER_HOST}:{SERVER_PORT}")
    uvicorn.run("src.server:app", host=SERVER_HOST, port=SERVER_PORT, log_level="info")

if __name__ == "__main__":
    main()
