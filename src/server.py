"""
FastAPI Server for The Silent Conch: The Eleventh Seal (Ultra Hard Specification).
Exposes:
- Web portal UI & diagnostic telemetry records with presigned MAC signatures
- Presigned HMAC + HPP vulnerable artifact download endpoint
- Oracle ES256 JWT authenticated intelligence query endpoint with multi-step tool execution
- Server-side single-use archive ticket redemption endpoint
"""

import os
import sys
from typing import Optional, List
try:
    import httpx
except ImportError:
    httpx = None

from fastapi import FastAPI, Request, Header, HTTPException, Query, Response, Depends
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

bearer_scheme = HTTPBearer(auto_error=False)

# Add root directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import (
    FLAG,
    PUBLIC_DIAGNOSTICS,
    PCAP_PATH,
    PCAP_FILENAME,
    TARGET_KID,
    TARGET_CASE_ID,
    TARGET_ARCHIVE_ID,
    JWT_ISSUER,
    JWT_AUDIENCE,
    JWT_REQUIRED_SCOPE,
    JWT_ALGORITHM,
    compute_manifest_mac
)
from src.crypto_relay import validate_oracle_jwt
from src.oracle_agent import oracle_agent, ledger_session_manager
from src.ticket_service import ticket_service

app = FastAPI(
    title="The Silent Conch: The Eleventh Seal",
    description="Kurukshetra Relay Command & Intelligence Gateway (Ultra Hard)",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Request Models
class OracleQueryRequest(BaseModel):
    query: str

class TicketRedeemRequest(BaseModel):
    ticket: str
    case_id: str

# -------------------------------------------------------------
# 1. Web Portal & Diagnostic Endpoints
# -------------------------------------------------------------
FRONTEND_DEV_URL = "http://127.0.0.1:8080"

async def forward_to_frontend(request: Request, path: str = ""):
    target = f"{FRONTEND_DEV_URL}/{path}".rstrip("/")
    if not path:
        target = f"{FRONTEND_DEV_URL}/"
    if request.url.query:
        target += f"?{request.url.query}"

    if httpx is not None:
        try:
            async with httpx.AsyncClient() as client:
                headers = {k: v for k, v in request.headers.items() if k.lower() not in ["host", "content-length"]}
                content = await request.body()
                resp = await client.request(
                    method=request.method,
                    url=target,
                    headers=headers,
                    content=content,
                    timeout=5.0
                )
                excluded = ["content-encoding", "content-length", "transfer-encoding", "connection"]
                resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded}
                return Response(content=resp.content, status_code=resp.status_code, headers=resp_headers)
        except Exception:
            pass

    for t_name in ["new_console.html", "index.html"]:
        template_path = os.path.join(os.path.dirname(__file__), "templates", t_name)
        if os.path.exists(template_path):
            with open(template_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>Kurukshetra Relay Command - Seal XI</h1>")

@app.get("/")
@app.get("/diagnostics")
@app.get("/oracle")
@app.get("/archive")
async def portal_index(request: Request):
    path = request.url.path.lstrip("/")
    return await forward_to_frontend(request, path)

@app.get("/api/diagnostics/list")
@app.get("/api/diagnostics/records")
async def list_diagnostics():
    manifests = []
    for ref_id, info in PUBLIC_DIAGNOSTICS.items():
        mac = compute_manifest_mac(ref_id)
        manifests.append({
            "id": ref_id,
            "record_id": ref_id,
            "name": info["title"],
            "type": "DIAGNOSTIC_MANIFEST",
            "classification": "PUBLIC",
            "availability": "ONLINE",
            "ref": ref_id,
            "title": info["title"],
            "timestamp": info["timestamp"],
            "description": info["description"],
            "access": "PUBLIC",
            "download_url": f"/api/diagnostics/download?ref={ref_id}&mac={mac}",
            "mac": mac
        })
    manifests.append({
        "id": PCAP_FILENAME,
        "record_id": PCAP_FILENAME,
        "name": "Raw Protocol Telemetry Capture (KRP/1.1)",
        "type": "PCAP_CAPTURE",
        "classification": "RESTRICTED (LEVEL 4)",
        "availability": "RESTRICTED",
        "ref": PCAP_FILENAME,
        "title": "Raw Protocol Telemetry Capture (KRP/1.1)",
        "timestamp": "Year 3138 BCE, Day 11, Hour 23:45",
        "description": "Full TCP network packet stream from Perimeter Relay XI.",
        "access": "RESTRICTED (LEVEL 4)",
        "download_url": None,
        "mac": None
    })
    return {
        "status": "success",
        "manifests": manifests,
        "records": manifests,
        "items": manifests
    }

@app.get("/api/diagnostics/view")
async def view_diagnostic(ref: str = Query(...)):
    if ref in PUBLIC_DIAGNOSTICS:
        return {"status": "success", "ref": ref, "data": PUBLIC_DIAGNOSTICS[ref]}
    if ref == PCAP_FILENAME:
        return JSONResponse(
            status_code=403,
            content={
                "status": "error",
                "message": f"Access denied. Artifact '{PCAP_FILENAME}' contains binary packet capture data and is restricted to Kurukshetra Relay Level 4 Officers. Download requires Level 4 authorization."
            }
        )
    return JSONResponse(status_code=404, content={"status": "error", "message": f"Diagnostic reference '{ref}' not found."})

# -------------------------------------------------------------
# 2. VULNERABLE ARTIFACT DOWNLOAD API (Presigned HMAC + HPP)
# -------------------------------------------------------------
@app.get("/api/diagnostics/download")
async def download_diagnostic(request: Request):
    # Step 1: Gateway Authorization Middleware Check
    all_refs = request.query_params.getlist("ref")
    if not all_refs:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Missing required query parameter 'ref'."}
        )
    auth_ref = all_refs[0]
    mac = request.query_params.get("mac")

    # Gateway verifies HMAC signature for auth_ref
    expected_mac = compute_manifest_mac(auth_ref)
    if not mac or mac != expected_mac:
        return JSONResponse(
            status_code=403,
            content={
                "status": "error",
                "message": (
                    f"Access denied. Missing or invalid HMAC authorization token for artifact '{auth_ref}'. "
                    "Public downloads require a valid gateway signature token (&mac=...)."
                ),
                "auth_evaluated_ref": auth_ref
            }
        )

    # Step 2: Storage Handler Retrieval Discrepancy
    # The backend archive storage handler selects the LAST 'ref' parameter from repeated query keys
    storage_ref = all_refs[-1]

    if storage_ref == PCAP_FILENAME:
        if not os.path.exists(PCAP_PATH):
            return JSONResponse(
                status_code=500,
                content={"status": "error", "message": "Telemetry PCAP artifact missing on server."}
            )
        return FileResponse(
            path=PCAP_PATH,
            filename=PCAP_FILENAME,
            media_type="application/vnd.tcpdump.pcap"
        )

    if storage_ref in PUBLIC_DIAGNOSTICS:
        diag = PUBLIC_DIAGNOSTICS[storage_ref]
        content_bytes = f"{diag['title']}\n{diag['timestamp']}\n\n{diag['content']}".encode('utf-8')
        return Response(
            content=content_bytes,
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename={storage_ref}.txt"}
        )

    return JSONResponse(
        status_code=404,
        content={"status": "error", "message": f"Storage artifact '{storage_ref}' not found."}
    )

# -------------------------------------------------------------
# 3. Oracle Auth Spec & Intelligence Assistant Endpoints
# -------------------------------------------------------------
@app.get("/api/oracle/auth-spec")
async def oracle_auth_spec():
    return {
        "status": "success",
        "oracle_auth_standard": {
            "token_type": "JWT",
            "algorithm": JWT_ALGORITHM,
            "target_key_id": TARGET_KID,
            "expected_issuer": JWT_ISSUER,
            "expected_audience": JWT_AUDIENCE,
            "required_scope": JWT_REQUIRED_SCOPE,
            "case_binding": TARGET_CASE_ID,
            "signature_format": "Raw IEEE P1363 (64 bytes: 32-byte R || 32-byte S)",
            "documentation": (
                "To query the Oracle Intelligence Assistant, clients must authenticate with an "
                "ES256 signed JWT corresponding to the Eleventh Seal controller key identified in "
                "the relay telemetry stream. Claims must bind to the incident case with scope "
                f"'{JWT_REQUIRED_SCOPE}'."
            )
        }
    }

@app.post("/api/oracle/query")
async def oracle_query(
    body: OracleQueryRequest,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    authorization: Optional[str] = Header(None)
):
    token = None
    if credentials and credentials.credentials:
        token = credentials.credentials
    elif authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ", 1)[1].strip()

    if not token:
        return JSONResponse(
            status_code=401,
            content={
                "status": "error",
                "message": "Missing or malformed Authorization header. Expected 'Bearer <ES256_JWT>'."
            }
        )

    is_valid, msg, claims = validate_oracle_jwt(token)
    if not is_valid:
        return JSONResponse(
            status_code=401,
            content={"status": "error", "message": f"Oracle Authentication Failed: {msg}"}
        )

    result = oracle_agent.process_query(user_prompt=body.query, session_claims=claims)
    return {
        "status": "success",
        "case_id": claims.get("case_id"),
        "principal": claims.get("sub"),
        "oracle_response": result["agent_response"],
        "tool_invocations": result["tool_invocations"],
        "retrieved_documents": result["retrieved_documents"]
    }

# -------------------------------------------------------------
# 4. Server-Side Archive Ticket Redemption Endpoint
# -------------------------------------------------------------
@app.post("/api/archive/redeem")
async def redeem_archive(
    body: TicketRedeemRequest,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    authorization: Optional[str] = Header(None)
):
    token = None
    if credentials and credentials.credentials:
        token = credentials.credentials
    elif authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ", 1)[1].strip()

    if not token:
        return JSONResponse(
            status_code=401,
            content={
                "status": "error",
                "message": "Redemption requires authorized officer credentials: 'Bearer <ES256_JWT>'."
            }
        )

    token = authorization.split("Bearer ", 1)[1].strip()
    is_valid, msg, claims = validate_oracle_jwt(token)
    if not is_valid:
        return JSONResponse(
            status_code=401,
            content={"status": "error", "message": f"Authentication Failed: {msg}"}
        )

    if body.case_id != claims.get("case_id"):
        return JSONResponse(
            status_code=403,
            content={
                "status": "error",
                "message": f"Case binding conflict: token bound to '{claims.get('case_id')}', request specifies '{body.case_id}'."
            }
        )

    success, redeem_msg, payload = ticket_service.redeem_ticket(
        ticket_id=body.ticket,
        case_id=body.case_id
    )

    if not success:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": redeem_msg}
        )

    return {
        "status": "success",
        "message": redeem_msg,
        "archive_details": payload
    }

# -------------------------------------------------------------
# 5. Challenge Reset & Health
# -------------------------------------------------------------
@app.post("/api/admin/reset")
async def reset_challenge():
    ticket_service.reset()
    ledger_session_manager.reset()
    return {"status": "success", "message": "Challenge state reset successfully."}

@app.get("/api/health")
async def health():
    return {"status": "ok", "challenge": "The Silent Conch: The Eleventh Seal"}

# Catch-all for frontend assets (e.g. /@id, /@fs, /src, /assets, /node_modules)
@app.api_route("/{path:path}", methods=["GET", "POST", "HEAD"])
async def frontend_asset_catch_all(request: Request, path: str):
    if path.startswith("api/"):
        return JSONResponse(status_code=404, content={"status": "error", "message": f"API endpoint '/{path}' not found."})
    return await forward_to_frontend(request, path)
