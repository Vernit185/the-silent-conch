"""
Server-side Ticket Service for Archive Redemption.
Enforces strict single-use validation, expiration, and case binding.
"""

import time
import uuid
import threading
from typing import Dict, Any, Tuple, Optional

from src.config import (
    FLAG,
    TARGET_CASE_ID,
    TARGET_ARCHIVE_ID
)

class TicketService:
    def __init__(self):
        self._lock = threading.Lock()
        self._tickets: Dict[str, Dict[str, Any]] = {}

    def create_ticket(
        self,
        archive_id: str = TARGET_ARCHIVE_ID,
        case_id: str = TARGET_CASE_ID,
        expires_in_seconds: int = 600
    ) -> str:
        ticket_id = f"TICKET-SEAL11-{uuid.uuid4().hex[:16]}"
        expires_at = time.time() + expires_in_seconds
        with self._lock:
            self._tickets[ticket_id] = {
                "archive_id": archive_id,
                "case_id": case_id,
                "created_at": time.time(),
                "expires_at": expires_at,
                "redeemed": False
            }
        return ticket_id

    def redeem_ticket(self, ticket_id: str, case_id: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if not ticket:
                return False, "Ticket not found or already redeemed.", None

            now = time.time()
            if now > ticket["expires_at"]:
                # Remove expired ticket
                del self._tickets[ticket_id]
                return False, "Ticket has expired.", None

            if ticket["case_id"] != case_id:
                return False, f"Ticket case binding mismatch: expected '{ticket['case_id']}', got '{case_id}'.", None

            if ticket["archive_id"] != TARGET_ARCHIVE_ID:
                return False, f"Invalid archive identifier '{ticket['archive_id']}'.", None

            # SINGLE-USE: Delete immediately upon successful redemption
            del self._tickets[ticket_id]

            return True, "Ticket successfully redeemed.", {
                "archive_name": "ELEVENTH_SEAL_KURUKSHETRA_WAR_CHRONICLE",
                "case_id": case_id,
                "flag": FLAG
            }

    def reset(self):
        with self._lock:
            self._tickets.clear()

# Global singleton
ticket_service = TicketService()
