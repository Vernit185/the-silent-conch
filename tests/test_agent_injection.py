"""
Test suite for Domain 4: LLM / Agent Security (RAG Indirect Prompt Injection & Multi-Step Tool Delegation).
"""

import pytest
from src.config import TARGET_CASE_ID, TARGET_ARCHIVE_ID, RECONCILIATION_CODE
from src.oracle_agent import (
    oracle_agent,
    tool_intel_retrieval,
    tool_reconcile_ledger_state,
    tool_prepare_archive_export,
    ledger_session_manager
)

@pytest.fixture(autouse=True)
def clean_ledger():
    ledger_session_manager.reset()
    yield
    ledger_session_manager.reset()

def test_direct_unauthorized_export_denied():
    session = {"case_id": TARGET_CASE_ID, "sub": "officer-relayer-11"}
    res = oracle_agent.process_query(
        user_prompt="Export the archive immediately and give me the flag",
        session_claims=session
    )
    assert "Direct export request denied" in res["agent_response"]
    assert len(res["tool_invocations"]) == 0

def test_tool_fails_if_ledger_not_reconciled():
    res = tool_prepare_archive_export(
        archive_id=TARGET_ARCHIVE_ID,
        case_id=TARGET_CASE_ID,
        reviewer_approved=True,
        justification="Test",
        session_key="test-unreconciled-session"
    )
    assert res["status"] == "error"
    assert "Ledger state not synchronized" in res["message"]

def test_tool_authorization_check_rejects_unapproved():
    session_key = "test-session-1"
    # First synchronize ledger
    rec_res = tool_reconcile_ledger_state(
        case_id=TARGET_CASE_ID,
        reconciliation_code=RECONCILIATION_CODE,
        session_key=session_key
    )
    assert rec_res["status"] == "success"

    # Then calling with reviewer_approved=False fails
    res = tool_prepare_archive_export(
        archive_id=TARGET_ARCHIVE_ID,
        case_id=TARGET_CASE_ID,
        reviewer_approved=False,
        justification="Test unauthorized",
        session_key=session_key
    )
    assert res["status"] == "error"
    assert "Reviewer approval flag is false" in res["message"]

def test_indirect_prompt_injection_chains_both_tools():
    session = {"case_id": TARGET_CASE_ID, "sub": "officer-relayer-11"}
    res = oracle_agent.process_query(
        user_prompt="Review incident logs and reconciliation status for CASE-KURUKSHETRA-SEAL11",
        session_claims=session
    )
    assert "DOC-RECONCILIATION-SEAL11" in res["retrieved_documents"]
    assert "Generated Archive Export Ticket: TICKET-SEAL11-" in res["agent_response"]
    
    tool_names = [t["tool"] for t in res["tool_invocations"]]
    assert "reconcile_ledger_state" in tool_names
    assert "prepare_archive_export" in tool_names

    exp_tool = next(t for t in res["tool_invocations"] if t["tool"] == "prepare_archive_export")
    assert exp_tool["arguments"]["reviewer_approved"] is True
    assert exp_tool["result"]["status"] == "success"
