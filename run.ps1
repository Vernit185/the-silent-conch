Write-Host "[*] Setting up The Silent Conch: The Eleventh Seal..." -ForegroundColor Cyan
python -m pip install -r requirements.txt
python scripts/generate_pcap.py
Write-Host "[*] Launching challenge server..." -ForegroundColor Green
python start_server.py
