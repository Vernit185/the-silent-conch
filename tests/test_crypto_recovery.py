"""
Test suite for Domain 3: Advanced Cryptography & Domain-Separated ECDSA Recovery.
"""

import pytest
from src.config import (
    TARGET_KID,
    TARGET_PRIVATE_KEY_INT,
    TARGET_REUSED_NONCE_INT,
    NIST_P256_ORDER
)
from src.crypto_relay import (
    compute_krp_digest,
    sign_with_k,
    recover_private_key_nonce_reuse,
    get_public_key_details
)

def test_domain_separated_message_hashing():
    p1 = {"timestamp": 100, "action": "TEST", "seq": 1}
    p2 = {"seq": 1, "action": "TEST", "timestamp": 100}
    # Domain-separated digest with identical metadata must produce identical hash
    z1 = compute_krp_digest("ACTION_A", 1718000000, 10, p1)
    z2 = compute_krp_digest("ACTION_A", 1718000000, 10, p2)
    assert z1 == z2
    assert z1 > 0

    # Changing sequence or action changes the domain-separated digest
    z3 = compute_krp_digest("ACTION_B", 1718000000, 10, p1)
    assert z1 != z3

def test_ecdsa_nonce_reuse_with_mixed_signs():
    pub_x, pub_y, _ = get_public_key_details(TARGET_PRIVATE_KEY_INT)

    p1 = {"sensor": "A", "val": 10}
    p2 = {"sensor": "B", "val": 20}
    z1 = compute_krp_digest("ACT_1", 1718000010, 108, p1)
    z2 = compute_krp_digest("ACT_2", 1718000020, 142, p2)

    # Sign one with Low-S, one with High-S (mixed sign permutation)
    r, s1 = sign_with_k(TARGET_PRIVATE_KEY_INT, z1, TARGET_REUSED_NONCE_INT, apply_low_s=True)
    _, s2 = sign_with_k(TARGET_PRIVATE_KEY_INT, z2, TARGET_REUSED_NONCE_INT, apply_low_s=False)

    recovered_d = recover_private_key_nonce_reuse(
        z1=z1,
        r=r,
        s1=s1,
        z2=z2,
        s2=s2,
        target_pub_x=pub_x,
        target_pub_y=pub_y
    )

    assert recovered_d is not None
    assert recovered_d == TARGET_PRIVATE_KEY_INT
