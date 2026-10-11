"""
Test suite for Oracle ES256 JWT Authentication.
"""

import time
import pytest
from src.config import (
    TARGET_KID,
    TARGET_PRIVATE_KEY_INT,
    TARGET_CASE_ID,
    JWT_ISSUER,
    JWT_AUDIENCE,
    JWT_REQUIRED_SCOPE
)
from src.crypto_relay import create_oracle_jwt, validate_oracle_jwt

def test_valid_jwt_authentication():
    token = create_oracle_jwt(
        d_int=TARGET_PRIVATE_KEY_INT,
        kid=TARGET_KID,
        case_id=TARGET_CASE_ID,
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
        scope=JWT_REQUIRED_SCOPE
    )
    is_valid, msg, claims = validate_oracle_jwt(token)
    assert is_valid, f"Validation failed: {msg}"
    assert claims["case_id"] == TARGET_CASE_ID
    assert claims["iss"] == JWT_ISSUER

def test_invalid_kid():
    token = create_oracle_jwt(
        d_int=TARGET_PRIVATE_KEY_INT,
        kid="wrong-kid-123"
    )
    is_valid, msg, _ = validate_oracle_jwt(token)
    assert not is_valid
    assert "Invalid key identifier" in msg

def test_invalid_issuer():
    token = create_oracle_jwt(
        d_int=TARGET_PRIVATE_KEY_INT,
        issuer="attacker.fake.org"
    )
    is_valid, msg, _ = validate_oracle_jwt(token)
    assert not is_valid
    assert "Invalid issuer" in msg

def test_invalid_audience():
    token = create_oracle_jwt(
        d_int=TARGET_PRIVATE_KEY_INT,
        audience="wrong.audience.internal"
    )
    is_valid, msg, _ = validate_oracle_jwt(token)
    assert not is_valid
    assert "Invalid audience" in msg

def test_missing_required_scope():
    token = create_oracle_jwt(
        d_int=TARGET_PRIVATE_KEY_INT,
        scope="intel:read"  # missing archive:delegate
    )
    is_valid, msg, _ = validate_oracle_jwt(token)
    assert not is_valid
    assert "Missing required authorization scope" in msg

def test_expired_token():
    token = create_oracle_jwt(
        d_int=TARGET_PRIVATE_KEY_INT,
        expires_in=-60  # Expired 60s ago
    )
    is_valid, msg, _ = validate_oracle_jwt(token)
    assert not is_valid
    assert "expired" in msg.lower()

def test_wrong_signature_key():
    fake_key = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    token = create_oracle_jwt(
        d_int=fake_key,
        kid=TARGET_KID
    )
    is_valid, msg, _ = validate_oracle_jwt(token)
    assert not is_valid
    assert "signature verification failed" in msg.lower()
