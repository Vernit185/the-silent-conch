"""
Cryptographic utility module for ECDSA P-256 and KRP/1.1 protocol.
Provides domain-separated hashing, low-S normalization, nonce-reuse recovery,
and ES256 JWT verification.
"""

import json
import struct
import hashlib
import time
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import jwt

from src.config import (
    NIST_P256_ORDER,
    TARGET_KID,
    TARGET_PRIVATE_KEY_INT,
    TARGET_REUSED_NONCE_INT,
    DECOY_KIDS,
    JWT_ISSUER,
    JWT_AUDIENCE,
    JWT_REQUIRED_SCOPE,
    JWT_ALGORITHM,
    TARGET_CASE_ID
)

# Domain Separator prefix for KRP/1.1
KRP_DOMAIN = b"KRP-V1.1-AUTH:"

# Helper to get EC private key object from integer
def get_private_key_from_int(d_int: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(d_int, ec.SECP256R1(), default_backend())

# Helper to get public key coordinates (x, y) and uncompressed SEC1 hex from int
def get_public_key_details(d_int: int) -> Tuple[int, int, str]:
    priv = get_private_key_from_int(d_int)
    pub = priv.public_key().public_numbers()
    hex_str = f"04{pub.x:064x}{pub.y:064x}"
    return pub.x, pub.y, hex_str

# Canonical JSON serialization (sorted keys, compact separators)
def canonical_serialize(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')

# Domain-Separated Digest Generation according to KRP/1.1 Specification
def compute_krp_digest(action: str, timestamp: int, seq: int, payload_dict: dict) -> int:
    action_bytes = action.encode('utf-8')
    meta = struct.pack(">QI", timestamp, seq)
    payload_canonical = canonical_serialize(payload_dict)
    payload_hash = hashlib.sha256(payload_canonical).digest()
    
    full_data = KRP_DOMAIN + action_bytes + b":" + meta + b":" + payload_hash
    digest = hashlib.sha256(full_data).digest()
    return int.from_bytes(digest, "big")

# Custom ECDSA signing with specified nonce k and optional low-S normalization
def sign_with_k(
    d_int: int,
    z_int: int,
    k_int: int,
    apply_low_s: bool = True
) -> Tuple[int, int]:
    n = NIST_P256_ORDER
    # Compute R = k * G
    k_key = ec.derive_private_key(k_int, ec.SECP256R1(), default_backend())
    r = k_key.public_key().public_numbers().x % n
    if r == 0:
        raise ValueError("r is zero, pick different nonce")
    
    k_inv = pow(k_int, -1, n)
    s = (k_inv * (z_int + r * d_int)) % n
    if s == 0:
        raise ValueError("s is zero, pick different nonce")
    
    if apply_low_s and s > n // 2:
        s = n - s
    
    return r, s

# Verify an ECDSA signature (r, s) on digest z against public key coordinates (pub_x, pub_y)
def verify_signature(pub_x: int, pub_y: int, z_int: int, r: int, s: int) -> bool:
    try:
        pub_numbers = ec.EllipticCurvePublicNumbers(pub_x, pub_y, ec.SECP256R1())
        pub_key = pub_numbers.public_key(default_backend())
        der_sig = encode_dss_signature(r, s)
        z_bytes = z_int.to_bytes(32, "big")
        pub_key.verify(der_sig, z_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        try:
            s_alt = NIST_P256_ORDER - s
            der_sig_alt = encode_dss_signature(r, s_alt)
            z_bytes = z_int.to_bytes(32, "big")
            pub_key.verify(der_sig_alt, z_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

# ECDSA Nonce-Reuse Recovery with Low-S / High-S Sign Handling
def recover_private_key_nonce_reuse(
    z1: int,
    r: int,
    s1: int,
    z2: int,
    s2: int,
    target_pub_x: int,
    target_pub_y: int
) -> Optional[int]:
    n = NIST_P256_ORDER
    r_inv = pow(r, -1, n)

    for sign1 in [1, -1]:
        for sign2 in [1, -1]:
            s1_cand = (sign1 * s1) % n
            s2_cand = (sign2 * s2) % n
            diff_s = (s1_cand - s2_cand) % n
            if diff_s == 0:
                continue
            
            diff_s_inv = pow(diff_s, -1, n)
            k_cand = ((z1 - z2) * diff_s_inv) % n
            d_cand = ((s1_cand * k_cand - z1) * r_inv) % n

            try:
                cand_key = ec.derive_private_key(d_cand, ec.SECP256R1(), default_backend())
                cand_pub = cand_key.public_key().public_numbers()
                if cand_pub.x == target_pub_x and cand_pub.y == target_pub_y:
                    return d_cand
            except Exception:
                continue

    return None

# Create valid ES256 JWT for the Oracle service using private key int
def create_oracle_jwt(
    d_int: int,
    kid: str = TARGET_KID,
    case_id: str = TARGET_CASE_ID,
    issuer: str = JWT_ISSUER,
    audience: str = JWT_AUDIENCE,
    scope: str = JWT_REQUIRED_SCOPE,
    expires_in: int = 3600
) -> str:
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": "officer-relayer-11",
        "scope": scope,
        "case_id": case_id,
        "iat": now - 60,
        "exp": now + expires_in
    }
    headers = {
        "alg": JWT_ALGORITHM,
        "typ": "JWT",
        "kid": kid
    }
    priv_key = get_private_key_from_int(d_int)
    token = jwt.encode(payload, priv_key, algorithm=JWT_ALGORITHM, headers=headers)
    return token

# Validate Oracle JWT against target public key and claims
def validate_oracle_jwt(token_str: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    try:
        unverified_header = jwt.get_unverified_header(token_str)
        if unverified_header.get("kid") != TARGET_KID:
            return False, f"Invalid key identifier: '{unverified_header.get('kid')}'. Expected '{TARGET_KID}'.", None
        if unverified_header.get("alg") != JWT_ALGORITHM:
            return False, f"Unsupported algorithm '{unverified_header.get('alg')}'. Expected '{JWT_ALGORITHM}'.", None

        target_priv = get_private_key_from_int(TARGET_PRIVATE_KEY_INT)
        target_pub = target_priv.public_key()

        payload = jwt.decode(
            token_str,
            target_pub,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            leeway=120
        )

        scopes = set(payload.get("scope", "").split())
        required_scopes = set(JWT_REQUIRED_SCOPE.split())
        for req in required_scopes:
            if req not in scopes:
                return False, f"Missing required authorization scope '{req}'.", None

        if payload.get("case_id") != TARGET_CASE_ID:
            return False, f"Invalid case binding '{payload.get('case_id')}'. Expected '{TARGET_CASE_ID}'.", None

        return True, "Authorized", payload
    except jwt.ExpiredSignatureError:
        return False, "Token signature has expired.", None
    except jwt.InvalidIssuerError:
        return False, f"Invalid issuer. Expected '{JWT_ISSUER}'.", None
    except jwt.InvalidAudienceError:
        return False, f"Invalid audience. Expected '{JWT_AUDIENCE}'.", None
    except jwt.InvalidSignatureError:
        return False, "Cryptographic signature verification failed (invalid ES256 key).", None
    except Exception as e:
        return False, f"JWT verification error: {str(e)}", None
