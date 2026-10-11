"""
Test suite for Distribution Hygiene and Secret Leakage Prevention.
"""

import os
import pytest
from src.config import FLAG, TARGET_PRIVATE_KEY_INT

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAYER_DIST_DIR = os.path.join(BASE_DIR, "player_dist")
STATIC_DIR = os.path.join(BASE_DIR, "src", "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "src", "templates")

def test_flag_not_in_player_dist():
    if not os.path.exists(PLAYER_DIST_DIR):
        pytest.skip("player_dist not yet created")

    priv_key_hex = f"{TARGET_PRIVATE_KEY_INT:x}"

    for root, _, files in os.walk(PLAYER_DIST_DIR):
        for f in files:
            path = os.path.join(root, f)
            with open(path, "rb") as file_obj:
                content = file_obj.read()
                assert FLAG.encode() not in content, f"Flag found in player dist file: {path}"
                assert priv_key_hex.encode() not in content, f"Private key hex found in player dist file: {path}"
                assert b"solve.py" not in content, f"Reference to author solver found in {path}"

def test_flag_not_in_frontend_static():
    for root, _, files in os.walk(STATIC_DIR):
        for f in files:
            path = os.path.join(root, f)
            with open(path, "rb") as file_obj:
                content = file_obj.read()
                assert FLAG.encode() not in content, f"Flag found in frontend static file: {path}"

    for root, _, files in os.walk(TEMPLATES_DIR):
        for f in files:
            path = os.path.join(root, f)
            with open(path, "rb") as file_obj:
                content = file_obj.read()
                assert FLAG.encode() not in content, f"Flag found in template: {path}"
