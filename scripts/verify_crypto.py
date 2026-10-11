"""
Author & Solver Verification Script (Ultra Hard Specification):
Reads seal11-relay-telemetry.pcap, reassembles TCP stream,
identifies target key and public key, rejects decoys,
computes domain-separated digests, solves for the ECDSA private key with sign permutations,
and confirms matching public key.
"""

import os
import sys
import json
import struct
from typing import List, Dict, Any, Tuple
from scapy.all import rdpcap, TCP, Raw

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import (
    PCAP_PATH,
    TARGET_KID,
    NIST_P256_ORDER,
    TARGET_PRIVATE_KEY_INT
)
from src.crypto_relay import (
    compute_krp_digest,
    recover_private_key_nonce_reuse,
    get_public_key_details
)

MAGIC_HEADER = b"KRP\x01"

def parse_pcap_stream(pcap_path: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    packets = rdpcap(pcap_path)
    
    # Reassemble TCP payload from server (port 9111) to client
    tcp_stream = bytearray()
    for pkt in packets:
        if TCP in pkt and pkt[TCP].sport == 9111 and Raw in pkt:
            tcp_stream.extend(pkt[Raw].load)
    
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
                try:
                    parsed_json = json.loads(payload_raw.decode('utf-8'))
                    messages.append(parsed_json)
                except Exception as e:
                    print(f"[!] JSON parse error at offset {idx}: {e}")
                idx = end_payload
            else:
                break
        else:
            idx += 1
            
    key_announce = None
    transaction_records = []
    for msg in messages:
        if msg.get("action") == "KEY_EXCHANGE_ANNOUNCE":
            key_announce = msg
        elif "signature" in msg and "signed_message" in msg:
            transaction_records.append(msg)
            
    return key_announce, transaction_records

def verify_and_solve(pcap_path: str = PCAP_PATH):
    print("=" * 70)
    print("FORENSIC & CRYPTOGRAPHIC VERIFICATION HARNESS (ULTRA HARD)")
    print("=" * 70)
    
    key_announce, transactions = parse_pcap_stream(pcap_path)
    assert key_announce is not None, "Missing KEY_EXCHANGE_ANNOUNCE in PCAP!"
    print(f"[+] Found Key Exchange Announce with {len(key_announce.get('keys', []))} keys.")
    
    target_key_entry = next(k for k in key_announce.get("keys", []) if k["kid"] == TARGET_KID)
    target_pub_hex = target_key_entry["public_key_hex"]
    target_pub_x = int(target_pub_hex[2:66], 16)
    target_pub_y = int(target_pub_hex[66:130], 16)
    print(f"[+] Target Key: {TARGET_KID}")
    print(f"[+] Target Public Key: (X=0x{target_pub_x:064x}, Y=0x{target_pub_y:064x})")
    
    # Group records by (kid, r)
    r_map = {}
    for tx in transactions:
        kid = tx.get("kid")
        sig = tx.get("signature", {})
        r_val = int(sig.get("r", "0"), 16)
        s_val = int(sig.get("s", "0"), 16)
        pair_key = (kid, r_val)
        if pair_key not in r_map:
            r_map[pair_key] = []
        r_map[pair_key].append((tx, s_val))
        
    target_pair = None
    for (kid, r_val), items in r_map.items():
        if len(items) > 1 and kid == TARGET_KID:
            tx1, s1 = items[0]
            tx2, s2 = items[1]
            if tx1["signed_message"] != tx2["signed_message"]:
                target_pair = (tx1, s1, tx2, s2, r_val)
                print(f"[+] GENUINE PAIR IDENTIFIED on '{TARGET_KID}' (r=0x{r_val:064x})!")

    assert target_pair is not None, "Failed to identify genuine nonce-reuse pair!"
    tx1, s1, tx2, s2, r_val = target_pair
    
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

    print(f"\n[+] Computed Domain-Separated SHA-256 Digests:")
    print(f"    z1 = 0x{z1:064x} (seq {m1.get('seq')})")
    print(f"    z2 = 0x{z2:064x} (seq {m2.get('seq')})")
    
    recovered_d = recover_private_key_nonce_reuse(
        z1=z1,
        r=r_val,
        s1=s1,
        z2=z2,
        s2=s2,
        target_pub_x=target_pub_x,
        target_pub_y=target_pub_y
    )
    
    assert recovered_d is not None, "Private key recovery failed!"
    print(f"\n[+] MATHEMATICAL KEY RECOVERY SUCCESSFUL!")
    print(f"    Recovered Private Key: 0x{recovered_d:064x}")
    assert recovered_d == TARGET_PRIVATE_KEY_INT, "Recovered key does not match target private key!"
    print("=" * 70)
    return recovered_d

if __name__ == "__main__":
    verify_and_solve()
