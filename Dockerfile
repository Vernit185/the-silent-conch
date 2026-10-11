FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (libpcap / tcpdump support for scapy)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and scripts
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY start_server.py .

# Generate PCAP artifact during build
RUN python scripts/generate_pcap.py

# Expose challenge port
EXPOSE 8000

ENV PORT=8000
ENV CHALLENGE_FLAG=KCTF{5h4nkh4_51l3n7_3l3v3n7h_534l_3cd54_n0nc3_unl0ck3d_48f9}

# Non-root user for security
RUN useradd -m ctfuser && chown -R ctfuser:ctfuser /app
USER ctfuser

CMD ["python", "start_server.py"]
