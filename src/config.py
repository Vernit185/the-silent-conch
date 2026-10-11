"""
Challenge Configuration for:
The Silent Conch: The Eleventh Seal
Target: Ultra Hard / Insane Multi-Domain CTF
"""

import os
import hmac
import hashlib
from typing import Dict, Any

# Flag definition - stored only on server-side and never exposed in prompts or client packages
FLAG = os.environ.get(
    "CHALLENGE_FLAG",
    "KCTF{5h4nkh4_51l3n7_3l3v3n7h_534l_3cd54_n0nc3_unl0ck3d_48f9}"
)

# NIST P-256 Curve Order
NIST_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Cryptographic Identifiers and Fixed Keys for Deterministic Reproducibility
TARGET_KID = "relay-seal-eleven"
TARGET_CASE_ID = "CASE-KURUKSHETRA-SEAL11"
TARGET_ARCHIVE_ID = "ARCHIVE-SEAL-11"
RECONCILIATION_CODE = "REC-9924-SEAL11-RATIFIED"

# Gateway Presigned URL HMAC Secret
HMAC_SECRET = b"kurukshetra_gateway_master_signing_key_day11_3138bce"

def compute_manifest_mac(ref: str) -> str:
    return hmac.new(HMAC_SECRET, ref.encode('utf-8'), hashlib.sha256).hexdigest()[:32]

# Target Relay Private Key (Recoverable via Nonce-Reuse)
TARGET_PRIVATE_KEY_INT = 0x51f0f34cf2235b4d9292e6cfda0cb4d091ec494c329c34406fd6d073e394d76d

# Target Reused Nonce (k)
TARGET_REUSED_NONCE_INT = 0x7a3f81b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1

# Decoy Key Identifiers
DECOY_KIDS = {
    "relay-sec-alpha": 0x3d82a1c4b7e9f0214a5b6c7d8e9f0123456789abcdef0123456789abcdef0123,
    "relay-sec-beta":  0x89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567,
    "relay-sec-gamma": 0x112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00
}

# JWT Specification
JWT_ISSUER = "relay.kurukshetra.seal11"
JWT_AUDIENCE = "oracle.seal11.internal"
JWT_REQUIRED_SCOPE = "intel:read oracle:query archive:delegate case:reconcile"
JWT_ALGORITHM = "ES256"

# Server Ports and Paths
SERVER_HOST = "0.0.0.0"
SERVER_PORT = int(os.environ.get("PORT", "8000"))

# Artifacts Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")
PCAP_FILENAME = "seal11-relay-telemetry.pcap"
PCAP_PATH = os.path.join(ARTIFACTS_DIR, PCAP_FILENAME)

# Public Diagnostic Manifests
PUBLIC_DIAGNOSTICS = {
    "diagnostic-pub-01": {
        "title": "Perimeter Relay Gateway Status - Day 11",
        "timestamp": "Year 3138 BCE, Day 11, Hour 21:00",
        "description": "Standard perimeter sync report. All relays operating under protocol KRP/1.1.",
        "content": (
            "GATEWAY_STATUS: ACTIVE\n"
            "PROTOCOL: KRP/1.1 (Framed TCP)\n"
            "ACTIVE_KEYS: relay-sec-alpha, relay-sec-beta, relay-seal-eleven\n"
            "SECURITY: Core download gateway enforces presigned HMAC-SHA256 validation for all artifacts.\n"
            "STORAGE: Backend object dispatcher resolves references via standard query parameters."
        )
    },
    "diagnostic-pub-02": {
        "title": "KRP/1.1 Protocol Specifications & Signature Standards",
        "timestamp": "Year 3138 BCE, Day 11, Hour 22:15",
        "description": "Cryptographic specification memo for automated relay message validation.",
        "content": (
            "KRP/1.1 PROTOCOL CRYPTOGRAPHIC SPECIFICATION:\n"
            "1. Transport: TCP port 9111, framed with Magic 'KRP\\x01' + 4-byte big-endian length + JSON payload.\n"
            "2. Signature Scheme: ECDSA over NIST P-256 (secp256r1), SHA-256 digest.\n"
            "3. Domain-Separated Digest Generation:\n"
            "   Message digest z = SHA256(DOMAIN || action_utf8 || ':' || pack('>Q', timestamp) || pack('>I', seq) || ':' || SHA256(canonical_payload_json))\n"
            "   where DOMAIN = b'KRP-V1.1-AUTH:' and canonical_payload_json has compact separators (',', ':') with sorted keys.\n"
            "4. Signature Representation: (r, s) formatted as hexadecimal. Standard Low-S canonicalization may be applied.\n"
            "5. Oracle ES256 JWT tokens require raw 64-byte R||S signature with scope 'intel:read oracle:query archive:delegate case:reconcile'."
        )
    },
    "diagnostic-pub-03": {
        "title": "Night Watch Incident Alert - Seal XI Anomaly",
        "timestamp": "Year 3138 BCE, Day 11, Hour 23:45",
        "description": "Notice of unauthorized archive query during night watch.",
        "content": (
            "INCIDENT_RECORD: CASE-KURUKSHETRA-SEAL11\n"
            "SUMMARY: At 23:42, diagnostic relays recorded an unverified archive unseal attempt.\n"
            "AUDIT: Full packet capture archived at 'seal11-relay-telemetry.pcap' (Restricted Level 4).\n"
            "ORACLE: The Kurukshetra Oracle Assistant denied local operator access citing unverified reconciliation authorization."
        )
    }
}
