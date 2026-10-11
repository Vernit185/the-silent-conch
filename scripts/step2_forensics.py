"""
Step 2 Forensics Walkthrough Script:
Reassembles TCP stream from seal11-relay-telemetry.pcap,
decodes the KRP/1.1 framed packets, analyzes all keys and signatures,
and explains the triage of all decoys.
"""

import os
import sys
import struct
import json
from scapy.all import rdpcap, TCP, Raw

pcap_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "artifacts", "seal11-relay-telemetry.pcap")

print("=" * 80)
print("STEP 2: DIGITAL FORENSICS - PACKET CAPTURE ANALYSIS")
print("=" * 80)
print(f"[*] Reading PCAP artifact: {pcap_path}")

packets = rdpcap(pcap_path)
print(f"[+] Loaded {len(packets)} raw network packets.")

# Filter and reassemble TCP payload on port 9111
tcp_stream = bytearray()
segment_count = 0
for i, pkt in enumerate(packets):
    if TCP in pkt and pkt[TCP].sport == 9111 and Raw in pkt:
        payload = pkt[Raw].load
        tcp_stream.extend(payload)
        segment_count += 1
        print(f"    - Packet #{i+1}: TCP Seq {pkt[TCP].seq}, Payload Length: {len(payload)} bytes")

print(f"\n[+] Total reassembled TCP stream: {len(tcp_stream)} bytes across {segment_count} data packets.")

# De-frame KRP/1.1 protocol messages
MAGIC_HEADER = b"KRP\x01"
messages = []
idx = 0
while idx + 8 <= len(tcp_stream):
    if tcp_stream[idx:idx+4] == MAGIC_HEADER:
        mlen = struct.unpack(">I", tcp_stream[idx+4:idx+8])[0]
        raw_json = tcp_stream[idx+8:idx+8+mlen]
        try:
            parsed = json.loads(raw_json.decode('utf-8'))
            messages.append(parsed)
        except Exception as e:
            print(f"[!] Decode error: {e}")
        idx += 8 + mlen
    else:
        idx += 1

print(f"[+] Successfully extracted {len(messages)} framed KRP/1.1 protocol messages.\n")

# 1. Handshake Analysis
print("-" * 80)
print("1. HANDSHAKE & PUBLIC KEY DISCOVERY (KEY_EXCHANGE_ANNOUNCE)")
print("-" * 80)
key_msg = next(m for m in messages if m.get("action") == "KEY_EXCHANGE_ANNOUNCE")
print(f"Incident Case Binding : {key_msg.get('case_id')}")
print(f"Protocol Version      : KRP/{key_msg.get('version')}")
print(f"Keys Announced in Exchange:")
for k in key_msg.get("keys", []):
    print(f"  • Key ID: {k['kid']:<18} | Curve: {k['curve']} | Role: {k.get('role')}")
    print(f"    Public Key Hex: {k['public_key_hex'][:40]}...{k['public_key_hex'][-16:]}")
    if "spec" in k:
        print(f"    Crypto Spec   : {k['spec']}")

# 2. Transaction Stream & Decoy Analysis
print("\n" + "-" * 80)
print("2. TRANSACTION LOGS & SIGNATURE TRIAGE")
print("-" * 80)
tx_records = [m for m in messages if "signature" in m]

for i, tx in enumerate(tx_records):
    kid = tx.get("kid")
    action = tx.get("action")
    sig = tx.get("signature", {})
    r = sig.get("r")
    s = sig.get("s")
    msg = tx.get("signed_message", {})
    seq = msg.get("seq")
    print(f"\n[Transaction #{i+1}]")
    print(f"  Key Identifier : {kid}")
    print(f"  Action / Seq   : {action} (seq: {seq})")
    print(f"  Signed Payload : {json.dumps(msg.get('payload', {}))}")
    print(f"  Signature (r)  : {r}")
    print(f"  Signature (s)  : {s}")

print("\n" + "-" * 80)
print("3. DECOY EVALUATION & PAIR ISOLATION")
print("-" * 80)

print("""
[DECOY 1 & 2 ANALYSIS: Cross-Key Nonce Collision]
  • Tx #1 (relay-sec-alpha) r = 0x406369581223d3721d5b9023e3ad6fc410dc21e8c0be788dab6147e5c013f383...
  • Tx #2 (relay-sec-beta)  r = 0x406369581223d3721d5b9023e3ad6fc410dc21e8c0be788dab6147e5c013f383...
  Observation: The 'r' values match!
  TRIAGE RESULT: REJECTED.
  Reason: They belong to two DIFFERENT key identifiers (relay-sec-alpha vs relay-sec-beta).
  ECDSA nonce reuse recovery requires the SAME private key d. Using two different keys produces nonsense.

[DECOY 3 ANALYSIS: Network Retransmission Replay]
  • Tx #3 (relay-sec-gamma) seq: 77, r = 0x79131127dd393538ae9257b5de9b042ac3b9186eb9a056bfa5a40d055104112b...
  • Tx #4 (relay-sec-gamma) seq: 77, r = 0x79131127dd393538ae9257b5de9b042ac3b9186eb9a056bfa5a40d055104112b...
  Observation: Identical 'r' values under the same key!
  TRIAGE RESULT: REJECTED.
  Reason: Messages are identical (m1 == m2). Thus z1 == z2 and s1 == s2.
  Calculating k = (z1 - z2) / (s1 - s2) mod n results in 0 / 0 (indeterminate division by zero).

[GENUINE PAIR IDENTIFIED: Target Controller 'relay-seal-eleven']
  • Tx #5: seq 108, action SEAL_TELEMETRY_DISPATCH
    Message: {"action":"SEAL_TELEMETRY_LOG_1","case_id":"CASE-KURUKSHETRA-SEAL11","payload":{"flux":412,"sensor":"GATE_NORTH","status":"LOCKED"},"seq":108,"timestamp":1718064120}
    r = 0x2f03d8b4d9c339d0af6017e58d026db64c1e7f94c8ecc3309e043dc8e558939f
    s1 = 0x20e8d72dd42dddad08f1c4977bcc409084ad36115dcfe848c455e888bd41c7b1

  • Tx #6: seq 142, action SEAL_TELEMETRY_DISPATCH (Segmented across TCP packets #11 and #12)
    Message: {"action":"SEAL_DISPATCH_RECORD_2","case_id":"CASE-KURUKSHETRA-SEAL11","payload":{"alert":"NIGHT_WATCH_SHADOW","cleared":false,"origin":"OUTPOST_9"},"seq":142,"timestamp":1718064380}
    r = 0x2f03d8b4d9c339d0af6017e58d026db64c1e7f94c8ecc3309e043dc8e558939f  <-- IDENTICAL r!
    s2 = 0x3e883192ee7b1f1007c3abd1a882bc7b28dfd6ad97d5bc9320287efdd024dfe1  <-- DIFFERENT s!

  CONCLUSION:
  - Key ID: relay-seal-eleven (The target Eleventh Seal Gateway!)
  - Two distinct messages signed using the SAME ephemeral nonce k!
  - We have (m1, z1, s1) and (m2, z2, s2) with identical r.
""")
print("=" * 80)
