import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# NIST P-256 curve order n
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def test_ecdsa_nonce_reuse():
    # Generate private key
    priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    priv_num = priv_key.private_numbers().private_value
    pub_key = priv_key.public_key()
    pub_numbers = pub_key.public_numbers()
    pub_x = pub_numbers.x
    pub_y = pub_numbers.y

    # Messages
    m1 = b'{"action":"TELEMETRY_RECORD_1","sensor":"GATE_NORTH","val":101}'
    m2 = b'{"action":"TELEMETRY_RECORD_2","sensor":"GATE_SOUTH","val":202}'

    z1 = int.from_bytes(hashlib.sha256(m1).digest(), "big")
    z2 = int.from_bytes(hashlib.sha256(m2).digest(), "big")

    # Fixed nonce k for demonstration
    # In ECDSA:
    # R = k * G = (r, y)
    # s = k^(-1) * (z + r * d) mod n
    k = 0x7a3f81b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1 % n

    # Compute R = k * G
    # We can create a temporary private key with value k to compute k * G
    k_key = ec.derive_private_key(k, ec.SECP256R1(), default_backend())
    r = k_key.public_key().public_numbers().x % n

    k_inv = pow(k, -1, n)
    s1_raw = (k_inv * (z1 + r * priv_num)) % n
    s2_raw = (k_inv * (z2 + r * priv_num)) % n

    # Apply low-S normalization (if s > n/2, s = n - s)
    s1_norm = s1_raw if s1_raw <= n // 2 else n - s1_raw
    s2_norm = s2_raw if s2_raw <= n // 2 else n - s2_raw

    # Now recover k and priv_num from (r, s1_norm), (r, s2_norm) and hashes z1, z2
    # Since signs could be flipped (+ or -), test all 4 combinations
    recovered_d = None
    for sign1 in [1, -1]:
        for sign2 in [1, -1]:
            s1_cand = (sign1 * s1_norm) % n
            s2_cand = (sign2 * s2_norm) % n
            diff_s = (s1_cand - s2_cand) % n
            if diff_s == 0:
                continue
            k_cand = ((z1 - z2) * pow(diff_s, -1, n)) % n
            d_cand = ((s1_cand * k_cand - z1) * pow(r, -1, n)) % n

            # Verify d_cand with public key
            try:
                cand_key = ec.derive_private_key(d_cand, ec.SECP256R1(), default_backend())
                cand_pub = cand_key.public_key().public_numbers()
                if cand_pub.x == pub_x and cand_pub.y == pub_y:
                    recovered_d = d_cand
                    break
            except Exception:
                continue
        if recovered_d:
            break

    assert recovered_d == priv_num, f"Recovery failed: {recovered_d} != {priv_num}"
    print(f"SUCCESS! Recovered private key: 0x{recovered_d:064x}")

if __name__ == "__main__":
    test_ecdsa_nonce_reuse()
