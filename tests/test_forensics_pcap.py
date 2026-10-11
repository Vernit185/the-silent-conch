"""
Test suite for Domain 2: Digital Forensics & Protocol Reconstruction.
"""

import os
import struct
import json
import pytest
from scapy.all import rdpcap, TCP, Raw

from src.config import PCAP_PATH, TARGET_KID, TARGET_CASE_ID
from scripts.generate_pcap import generate_telemetry_pcap

@pytest.fixture(scope="module")
def ensure_pcap():
    if not os.path.exists(PCAP_PATH):
        generate_telemetry_pcap()
    return PCAP_PATH

def test_pcap_structure(ensure_pcap):
    packets = rdpcap(ensure_pcap)
    assert len(packets) >= 10, "PCAP should contain full handshake and transaction records"
    # Ensure TCP traffic on port 9111
    has_9111 = any(TCP in p and (p[TCP].sport == 9111 or p[TCP].dport == 9111) for p in packets)
    assert has_9111, "Expected TCP traffic on relay port 9111"

def test_stream_reassembly_and_key_announce(ensure_pcap):
    packets = rdpcap(ensure_pcap)
    stream = bytearray()
    for p in packets:
        if TCP in p and p[TCP].sport == 9111 and Raw in p:
            stream.extend(p[Raw].load)

    # Frame parsing
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

    # Handshake key announce
    key_announce = next((m for m in messages if m.get("action") == "KEY_EXCHANGE_ANNOUNCE"), None)
    assert key_announce is not None
    assert key_announce.get("case_id") == TARGET_CASE_ID
    target_key = next((k for k in key_announce.get("keys", []) if k["kid"] == TARGET_KID), None)
    assert target_key is not None
    assert target_key["curve"] == "P-256"
    assert target_key["public_key_hex"].startswith("04")

def test_decoy_rejection_and_genuine_pair(ensure_pcap):
    packets = rdpcap(ensure_pcap)
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

    # Decoy: relay-sec-gamma has identical messages (replay decoy)
    for (kid, r), records in r_map.items():
        if kid == "relay-sec-gamma":
            assert len(records) == 2
            assert records[0][0]["signed_message"] == records[1][0]["signed_message"], "Replay decoy messages must be identical"

    # Genuine: relay-seal-eleven has distinct messages signed with same r
    genuine = r_map.get((TARGET_KID, int(transactions[-1]["signature"]["r"], 16)))
    assert genuine is not None
    assert len(genuine) == 2
    assert genuine[0][0]["signed_message"] != genuine[1][0]["signed_message"]
