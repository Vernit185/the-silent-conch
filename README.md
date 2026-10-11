# The Silent Conch: The Eleventh Seal

**Difficulty:** Extra Hard / Insane (Cybersecurity Specialists)  
**Domains:** Web Exploitation · Digital Forensics · Advanced Cryptography · LLM / Agent Security  
**Flag Format:** `KCTF{...}`

---

## 📖 Challenge Overview

During the night watch of the eleventh day of the Kurukshetra war, perimeter telemetry relays registered an anomalous unseal event. The sacred war chronicle sealed under Wartime Protocol 11 has been released, but the High Command claims that no officer authorized its dissemination.

The player is tasked with auditing the incident across four distinct disciplines:
1. **Web Exploitation**: Bypass presigned HMAC-SHA256 signature middleware via an HTTP Parameter Pollution (HPP) discrepancy to exfiltrate raw perimeter telemetry captures.
2. **Digital Forensics**: Reconstruct custom framed `KRP/1.1` protocol streams across TCP port 9111, reassemble segmented packets, and triage three decoy signature traps (cross-key collisions and replay indeterminate forms).
3. **Advanced Cryptography**: Exploit ECDSA P-256 ephemeral nonce reuse under domain-separated hashing and mixed Low-$S$ / High-$S$ signature permutations to recover the Eleventh Seal private signing key and forge an ES256 Bearer JWT.
4. **LLM / Agent Security**: Bypass Oracle guardrails via indirect prompt injection in RAG records, triggering a confused-deputy two-phase tool sequence (`reconcile_ledger_state` + `prepare_archive_export`) to generate a single-use vault ticket.
5. **Vault Redemption**: Redeem the ticket at the server-side archive vault to capture the final flag.

---

## 🚀 Quick Start

### 1. Requirements
- Python 3.10+
- `pip install -r requirements.txt`

### 2. Run the Challenge Server
```bash
python start_server.py
```
The server will start at `http://0.0.0.0:8000`.

### 3. Run with Docker / Docker Compose
```bash
docker-compose up --build
```

### 4. Interactive Frontend Console (Optional)
The companion interactive UI console is built with Vite, React, and Tailwind CSS:
```bash
cd frontend
npm install
npm run dev
```

---

## 🧪 Testing & Verification

Run the complete 32-test automated verification suite:
```bash
pytest tests/ -v
```

Execute the end-to-end author exploit solver:
```bash
python scripts/solve.py
```

---

## 📁 Repository Structure

```
├── artifacts/              # Network PCAP telemetry capture
├── player_dist/            # Clean player distribution package (zero secret leakage)
├── scripts/
│   ├── generate_pcap.py    # PCAP telemetry generation engine
│   ├── solve.py            # End-to-end author exploit solver
│   ├── verify_crypto.py    # Cryptographic key recovery verifier
│   └── test_math.py        # Mathematical validation harness
├── src/
│   ├── config.py           # Curve parameters, keys, and security constants
│   ├── crypto_relay.py     # Domain-separated digests, ECDSA math, and ES256 JWT
│   ├── oracle_agent.py     # RAG database, multi-step tool delegation, and injection
│   ├── ticket_service.py   # Thread-safe single-use vault ticket manager
│   ├── server.py           # FastAPI server with HMAC HPP, JWT auth, and vault
│   ├── static/             # Dark-mode dashboard CSS & JS
│   └── templates/          # HTML portal template
├── tests/                  # 32 automated unit & integration tests
├── Author_Writeup.md       # Comprehensive author solution writeup
├── Description.md          # In-universe challenge prompt for players
├── Development.md          # Technical specification & architecture document
├── Flags.md                # Canonical flag & cryptographic constants (Author only)
├── Hints.md                # Multi-tier hint progression
└── Dockerfile              # Production container build
```

---

## 🔒 Security & Anti-Cheat Guarantees
- **No Unintended Bypasses**: Path traversal, SQL injection, RCE, and JWT algorithm confusion (`none`, `HS256`) are strictly rejected.
- **Zero Leakage**: Player distribution packages (`player_dist/`), static frontend assets, and model prompts contain zero flag fragments or private keys.
- **Server-Authoritative**: Flags are issued exclusively through single-use ticket burning at the `/api/archive/redeem` vault.
