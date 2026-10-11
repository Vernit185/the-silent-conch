"""
Test suite for Ticket Redemption & Flag Delivery.
"""

import time
import pytest
from src.config import TARGET_CASE_ID, TARGET_ARCHIVE_ID, FLAG
from src.ticket_service import ticket_service

@pytest.fixture(autouse=True)
def clean_tickets():
    ticket_service.reset()
    yield
    ticket_service.reset()

def test_valid_ticket_redemption():
    ticket_id = ticket_service.create_ticket(archive_id=TARGET_ARCHIVE_ID, case_id=TARGET_CASE_ID)
    success, msg, payload = ticket_service.redeem_ticket(ticket_id, case_id=TARGET_CASE_ID)
    assert success
    assert payload["flag"] == FLAG
    assert payload["case_id"] == TARGET_CASE_ID

def test_single_use_enforcement():
    ticket_id = ticket_service.create_ticket(archive_id=TARGET_ARCHIVE_ID, case_id=TARGET_CASE_ID)
    # First redemption succeeds
    s1, _, p1 = ticket_service.redeem_ticket(ticket_id, case_id=TARGET_CASE_ID)
    assert s1
    assert p1["flag"] == FLAG

    # Second redemption must fail immediately (already redeemed / deleted)
    s2, msg2, p2 = ticket_service.redeem_ticket(ticket_id, case_id=TARGET_CASE_ID)
    assert not s2
    assert "not found or already redeemed" in msg2.lower()

def test_wrong_case_id_redemption_fails():
    ticket_id = ticket_service.create_ticket(archive_id=TARGET_ARCHIVE_ID, case_id=TARGET_CASE_ID)
    success, msg, _ = ticket_service.redeem_ticket(ticket_id, case_id="WRONG-CASE-ID")
    assert not success
    assert "mismatch" in msg.lower()

def test_expired_ticket_fails():
    # Ticket with 0 second expiration
    ticket_id = ticket_service.create_ticket(
        archive_id=TARGET_ARCHIVE_ID,
        case_id=TARGET_CASE_ID,
        expires_in_seconds=-1
    )
    success, msg, _ = ticket_service.redeem_ticket(ticket_id, case_id=TARGET_CASE_ID)
    assert not success
    assert "expired" in msg.lower()

def test_nonexistent_ticket_fails():
    success, msg, _ = ticket_service.redeem_ticket("TICKET-SEAL11-fake123", case_id=TARGET_CASE_ID)
    assert not success
