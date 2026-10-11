"""
Ultra Hard PCAP Generator for The Silent Conch: The Eleventh Seal.
Generates an authentic PCAP capturing:
- Background network noise (DNS, TLS on port 443, ICMP echo)
- KRP/1.1 framed protocol traffic on port 9111
- Key exchange announce with P-256 controller keys
- Decoy cross-key collision and replay transactions
- Out-of-order / segmented TCP streams
- Domain-separated ECDSA P-256 signatures with mixed Low-S and High-S normalization
"""

import os
import sys
import json
import struct
from typing import List

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, ICMP, wrpcap
from src.config import (
    PCAP_PATH,
    TARGET_KID,
    TARGET_CASE_ID,
    TARGET_PRIVATE_KEY_INT,
    TARGET_REUSED_NONCE_INT,
    DECOY_KIDS,
    ARTIFACTS_DIR
)
from src.crypto_relay import (
    get_public_key_details,
    compute_krp_digest,
    sign_with_k
)

MAGIC_HEADER = b"KRP\x01"

def frame_krp_message(data_dict: dict) -> bytes:
    payload_bytes = json.dumps(data_dict, separators=(',', ':')).encode('utf-8')
    length_prefix = struct.pack(">I", len(payload_bytes))
    return MAGIC_HEADER + length_prefix + payload_bytes

def generate_telemetry_pcap():
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    
    _, _, target_pub_hex = get_public_key_details(TARGET_PRIVATE_KEY_INT)
    _, _, alpha_pub_hex = get_public_key_details(DECOY_KIDS["relay-sec-alpha"])
    _, _, beta_pub_hex = get_public_key_details(DECOY_KIDS["relay-sec-beta"])
    _, _, gamma_pub_hex = get_public_key_details(DECOY_KIDS["relay-sec-gamma"])

    packets = []
    client_ip = "10.11.1.100"
    server_ip = "10.11.1.11"
    client_port = 54322
    server_port = 9111
    
    base_time = 1718064000.0
    client_seq = 1000
    server_seq = 2000

    def make_eth_ip():
        return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=client_ip, dst=server_ip)

    def make_rev_eth_ip():
        return Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") / IP(src=server_ip, dst=client_ip)

    # ---------------------------------------------------------
    # 0. REALISTIC BACKGROUND NETWORK NOISE (DNS & ICMP)
    # ---------------------------------------------------------
    # DNS Query & Response
    pkt_dns_q = Ether() / IP(src=client_ip, dst="10.11.0.1") / UDP(sport=49152, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="relay.kurukshetra.internal")
    )
    pkt_dns_q.time = base_time - 0.050
    packets.append(pkt_dns_q)

    pkt_dns_r = Ether() / IP(src="10.11.0.1", dst=client_ip) / UDP(sport=53, dport=49152) / DNS(
        qr=1, aa=1, qd=DNSQR(qname="relay.kurukshetra.internal"),
        an=DNSRR(rrname="relay.kurukshetra.internal", rdata=server_ip)
    )
    pkt_dns_r.time = base_time - 0.045
    packets.append(pkt_dns_r)

    # ICMP Echo ping
    pkt_ping = Ether() / IP(src=client_ip, dst=server_ip) / ICMP(type=8, code=0)
    pkt_ping.time = base_time - 0.020
    packets.append(pkt_ping)

    pkt_pong = Ether() / IP(src=server_ip, dst=client_ip) / ICMP(type=0, code=0)
    pkt_pong.time = base_time - 0.018
    packets.append(pkt_pong)

    # Red herring TLS connection attempt on port 443
    pkt_tls_syn = make_eth_ip() / TCP(sport=54320, dport=443, flags="S", seq=500, ack=0)
    pkt_tls_syn.time = base_time - 0.010
    packets.append(pkt_tls_syn)

    pkt_tls_rst = make_rev_eth_ip() / TCP(sport=443, dport=54320, flags="RA", seq=0, ack=501)
    pkt_tls_rst.time = base_time - 0.008
    packets.append(pkt_tls_rst)

    # ---------------------------------------------------------
    # 1. TCP HANDSHAKE ON PORT 9111 (SYN, SYN-ACK, ACK)
    # ---------------------------------------------------------
    pkt_syn = make_eth_ip() / TCP(sport=client_port, dport=server_port, flags="S", seq=client_seq, ack=0)
    pkt_syn.time = base_time
    packets.append(pkt_syn)
    client_seq += 1

    pkt_synack = make_rev_eth_ip() / TCP(sport=server_port, dport=client_port, flags="SA", seq=server_seq, ack=client_seq)
    pkt_synack.time = base_time + 0.002
    packets.append(pkt_synack)
    server_seq += 1

    pkt_ack = make_eth_ip() / TCP(sport=client_port, dport=server_port, flags="A", seq=client_seq, ack=server_seq)
    pkt_ack.time = base_time + 0.003
    packets.append(pkt_ack)

    # ---------------------------------------------------------
    # 2. KEY EXCHANGE ANNOUNCE
    # ---------------------------------------------------------
    key_exchange_msg = {
        "version": "1.1",
        "seq": 1,
        "action": "KEY_EXCHANGE_ANNOUNCE",
        "case_id": TARGET_CASE_ID,
        "timestamp": int(base_time),
        "keys": [
            {
                "kid": TARGET_KID,
                "curve": "P-256",
                "public_key_hex": target_pub_hex,
                "role": "Eleventh Seal Gateway Controller",
                "spec": "ES256; canonical payload = compact JSON sorted keys; hash = SHA-256; low-S enforced"
            },
            {
                "kid": "relay-sec-alpha",
                "curve": "P-256",
                "public_key_hex": alpha_pub_hex,
                "role": "Perimeter Relay Alpha"
            },
            {
                "kid": "relay-sec-beta",
                "curve": "P-256",
                "public_key_hex": beta_pub_hex,
                "role": "Perimeter Relay Beta"
            },
            {
                "kid": "relay-sec-gamma",
                "curve": "P-256",
                "public_key_hex": gamma_pub_hex,
                "role": "Outpost Telemetry Gamma"
            }
        ]
    }
    ke_raw = frame_krp_message(key_exchange_msg)
    pkt_ke = make_rev_eth_ip() / TCP(sport=server_port, dport=client_port, flags="PA", seq=server_seq, ack=client_seq) / ke_raw
    pkt_ke.time = base_time + 0.010
    packets.append(pkt_ke)
    server_seq += len(ke_raw)

    pkt_ack2 = make_eth_ip() / TCP(sport=client_port, dport=server_port, flags="A", seq=client_seq, ack=server_seq)
    pkt_ack2.time = base_time + 0.012
    packets.append(pkt_ack2)

    # ---------------------------------------------------------
    # 3. DECOY TRANSACTIONS (DOMAIN SEPARATED)
    # ---------------------------------------------------------
    # Decoy 1: relay-sec-alpha normal transaction
    p_alpha = {"status": "GREEN", "gate": "NORTH_WEST"}
    ts_alpha = int(base_time + 10)
    seq_alpha = 12
    z_alpha = compute_krp_digest("PERIMETER_HEARTBEAT", ts_alpha, seq_alpha, p_alpha)
    k_alpha = 0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0001
    r_alpha, s_alpha = sign_with_k(DECOY_KIDS["relay-sec-alpha"], z_alpha, k_alpha, apply_low_s=True)
    msg_alpha_framed = frame_krp_message({
        "action": "PERIMETER_DISPATCH",
        "kid": "relay-sec-alpha",
        "signed_message": {
            "action": "PERIMETER_HEARTBEAT",
            "case_id": "CASE-KURUKSHETRA-ALPHA",
            "payload": p_alpha,
            "seq": seq_alpha,
            "timestamp": ts_alpha
        },
        "signature": {"r": f"0x{r_alpha:064x}", "s": f"0x{s_alpha:064x}"}
    })
    pkt_alpha = make_rev_eth_ip() / TCP(sport=server_port, dport=client_port, flags="PA", seq=server_seq, ack=client_seq) / msg_alpha_framed
    pkt_alpha.time = base_time + 0.030
    packets.append(pkt_alpha)
    server_seq += len(msg_alpha_framed)

    # Decoy 2: Cross-key fake collision decoy (same r on relay-sec-beta)
    p_beta = {"node": "CHARIOT_DIVISION_3", "sync_val": 999}
    ts_beta = int(base_time + 15)
    seq_beta = 45
    z_beta = compute_krp_digest("DECOY_SYNCHRONIZATION", ts_beta, seq_beta, p_beta)
    r_beta_decoy, s_beta_decoy = sign_with_k(DECOY_KIDS["relay-sec-beta"], z_beta, k_alpha, apply_low_s=True)
    msg_beta_framed = frame_krp_message({
        "action": "PERIMETER_DISPATCH",
        "kid": "relay-sec-beta",
        "signed_message": {
            "action": "DECOY_SYNCHRONIZATION",
            "case_id": "CASE-KURUKSHETRA-BETA",
            "payload": p_beta,
            "seq": seq_beta,
            "timestamp": ts_beta
        },
        "signature": {"r": f"0x{r_beta_decoy:064x}", "s": f"0x{s_beta_decoy:064x}"}
    })
    pkt_beta = make_rev_eth_ip() / TCP(sport=server_port, dport=client_port, flags="PA", seq=server_seq, ack=client_seq) / msg_beta_framed
    pkt_beta.time = base_time + 0.045
    packets.append(pkt_beta)
    server_seq += len(msg_beta_framed)

    # Decoy 3: Replay packet from relay-sec-gamma (identical message & sig -> 0/0)
    p_gamma = {"ping_count": 1}
    ts_gamma = int(base_time + 20)
    seq_gamma = 77
    z_gamma = compute_krp_digest("OUTPOST_PING", ts_gamma, seq_gamma, p_gamma)
    k_gamma = 0x55556666777788889999aaaabbbbccccddddeeeeffff00001111222233334444
    r_gamma, s_gamma = sign_with_k(DECOY_KIDS["relay-sec-gamma"], z_gamma, k_gamma, apply_low_s=True)
    msg_gamma_framed = frame_krp_message({
        "action": "OUTPOST_REPORT",
        "kid": "relay-sec-gamma",
        "signed_message": {
            "action": "OUTPOST_PING",
            "case_id": "CASE-KURUKSHETRA-GAMMA",
            "payload": p_gamma,
            "seq": seq_gamma,
            "timestamp": ts_gamma
        },
        "signature": {"r": f"0x{r_gamma:064x}", "s": f"0x{s_gamma:064x}"}
    })
    pkt_gamma1 = make_rev_eth_ip() / TCP(sport=server_port, dport=client_port, flags="PA", seq=server_seq, ack=client_seq) / msg_gamma_framed
    pkt_gamma1.time = base_time + 0.060
    packets.append(pkt_gamma1)
    server_seq += len(msg_gamma_framed)

    pkt_gamma2 = make_rev_eth_ip() / TCP(sport=server_port, dport=client_port, flags="PA", seq=server_seq, ack=client_seq) / msg_gamma_framed
    pkt_gamma2.time = base_time + 0.065
    packets.append(pkt_gamma2)
    server_seq += len(msg_gamma_framed)

    # ---------------------------------------------------------
    # 4. GENUINE TARGET NONCE-REUSE PAIR on 'relay-seal-eleven'
    # ---------------------------------------------------------
    # Message 1 (Low-S normalized):
    p_t1 = {"flux": 412, "sensor": "GATE_NORTH", "status": "LOCKED"}
    ts_t1 = 1718064120
    seq_t1 = 108
    z_target_1 = compute_krp_digest("SEAL_TELEMETRY_LOG_1", ts_t1, seq_t1, p_t1)
    r_target, s1_target = sign_with_k(
        TARGET_PRIVATE_KEY_INT,
        z_target_1,
        TARGET_REUSED_NONCE_INT,
        apply_low_s=True
    )
    msg_target_1_framed = frame_krp_message({
        "action": "SEAL_TELEMETRY_DISPATCH",
        "kid": TARGET_KID,
        "signed_message": {
            "action": "SEAL_TELEMETRY_LOG_1",
            "case_id": TARGET_CASE_ID,
            "payload": p_t1,
            "seq": seq_t1,
            "timestamp": ts_t1
        },
        "signature": {"r": f"0x{r_target:064x}", "s": f"0x{s1_target:064x}"}
    })
    pkt_target_1 = make_rev_eth_ip() / TCP(sport=server_port, dport=client_port, flags="PA", seq=server_seq, ack=client_seq) / msg_target_1_framed
    pkt_target_1.time = base_time + 0.080
    packets.append(pkt_target_1)
    server_seq += len(msg_target_1_framed)

    # Message 2 (High-S, un-normalized to test sign permutation handling):
    p_t2 = {"alert": "NIGHT_WATCH_SHADOW", "cleared": False, "origin": "OUTPOST_9"}
    ts_t2 = 1718064380
    seq_t2 = 142
    z_target_2 = compute_krp_digest("SEAL_DISPATCH_RECORD_2", ts_t2, seq_t2, p_t2)
    _, s2_target = sign_with_k(
        TARGET_PRIVATE_KEY_INT,
        z_target_2,
        TARGET_REUSED_NONCE_INT,
        apply_low_s=False
    )
    msg_target_2_framed = frame_krp_message({
        "action": "SEAL_TELEMETRY_DISPATCH",
        "kid": TARGET_KID,
        "signed_message": {
            "action": "SEAL_DISPATCH_RECORD_2",
            "case_id": TARGET_CASE_ID,
            "payload": p_t2,
            "seq": seq_t2,
            "timestamp": ts_t2
        },
        "signature": {"r": f"0x{r_target:064x}", "s": f"0x{s2_target:064x}"}
    })

    # Realistic TCP Segmentation across two packets:
    split_offset = 120
    chunk_1 = msg_target_2_framed[:split_offset]
    chunk_2 = msg_target_2_framed[split_offset:]

    pkt_target_2a = make_rev_eth_ip() / TCP(sport=server_port, dport=client_port, flags="A", seq=server_seq, ack=client_seq) / chunk_1
    pkt_target_2a.time = base_time + 0.100
    packets.append(pkt_target_2a)
    server_seq += len(chunk_1)

    pkt_target_2b = make_rev_eth_ip() / TCP(sport=server_port, dport=client_port, flags="PA", seq=server_seq, ack=client_seq) / chunk_2
    pkt_target_2b.time = base_time + 0.105
    packets.append(pkt_target_2b)
    server_seq += len(chunk_2)

    # ---------------------------------------------------------
    # 5. TCP TEARDOWN
    # ---------------------------------------------------------
    pkt_fin = make_rev_eth_ip() / TCP(sport=server_port, dport=client_port, flags="FA", seq=server_seq, ack=client_seq)
    pkt_fin.time = base_time + 0.120
    packets.append(pkt_fin)
    server_seq += 1

    pkt_cfin = make_eth_ip() / TCP(sport=client_port, dport=server_port, flags="FA", seq=client_seq, ack=server_seq)
    pkt_cfin.time = base_time + 0.122
    packets.append(pkt_cfin)
    client_seq += 1

    pkt_cack = make_rev_eth_ip() / TCP(sport=server_port, dport=client_port, flags="A", seq=server_seq, ack=client_seq)
    pkt_cack.time = base_time + 0.125
    packets.append(pkt_cack)

    # Write out PCAP
    wrpcap(PCAP_PATH, packets)
    print(f"Successfully generated Ultra Hard PCAP at: {PCAP_PATH} ({len(packets)} packets, {os.path.getsize(PCAP_PATH)} bytes)")

if __name__ == "__main__":
    generate_telemetry_pcap()
