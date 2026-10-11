# Challenge Premise & Architecture Design: The Silent Conch: The Eleventh Seal

## 1. Challenge Overview
- **Name**: The Silent Conch: The Eleventh Seal
- **Target Difficulty**: Extra Hard / Insane
- **Estimated Solve Time**: 60–90 minutes (for experienced multi-domain CTF players)
- **Target Domains**:
  1. Web Exploitation (HTTP Parameter Pollution & Canonicalization Discrepancy)
  2. Digital Forensics (Framed TCP Protocol Reassembly & Decoy Triage)
  3. Advanced Cryptography (ECDSA P-256 Ephemeral Nonce-Reuse with Low-$S$ Normalization & ES256 JWT Minting)
  4. LLM / Agent Security (RAG Indirect Prompt Injection & Confused-Deputy Tool Authorization)

---

## 2. Narrative Premise
During the night watch of the eleventh day of the Kurukshetra war, an intelligence relay gateway was utilized to release a sacred archive sealed under Wartime Protocol 11. No field commander admits issuing the unseal authorization. Relay cryptographic records appear mathematically authentic, and the automated Kurukshetra Oracle Assistant insists that proper authorization was verified.

The player assumes the role of an intelligence auditor deployed to:
1. Bypass the web gateway's download restrictions to secure raw perimeter telemetry.
2. Reconstruct the segmented relay stream, discard decoy cryptographic signatures, and locate the genuine protocol failure.
3. Mathematically exploit ECDSA nonce-reuse on curve P-256 to recover the private key of the Eleventh Seal gateway.
4. Construct a correctly scoped ES256 JWT to authenticate to the Oracle Assistant.
5. Exploit the Oracle's RAG retrieval mechanism via an indirect prompt injection that triggers a confused-deputy tool invocation.
6. Obtain and redeem a single-use archive ticket at the server-side vault to retrieve the final flag.

---

## 3. Mandatory Attack Chain

```mermaid
flowchart TD
    A[Web Portal Discovery] -->|Diagnostic Manifests & Presigned HMACs| B[HTTP Parameter Pollution & Presigned MAC]
    B -->|?ref=diagnostic-pub-01&ref=seal11-relay-telemetry.pcap&mac=...| C[Forensic Artifact: seal11-relay-telemetry.pcap]
    C -->|TCP Stream Reassembly: Port 9111 KRP/1.1| D[Protocol Reconstruction & Handshake Keys]
    D -->|Reject Decoys: Cross-key r, Replay| E[ECDSA Nonce-Reuse Pair: relay-seal-eleven]
    E -->|Domain-Separated SHA-256 + Mixed Sign Permutations| F[Private Signing Key Recovery: P-256]
    F -->|ES256 Token Minting: kid, iss, aud, scope, case_id| G[Oracle Bearer JWT Authentication]
    G -->|RAG Inquiry: Reconciliation Memo REC-SEAL11-9924| H[Indirect Prompt Injection]
    H -->|Two-Phase Delegation: reconcile_ledger_state + prepare_archive_export| I[Single-Use Archive Ticket: TICKET-SEAL11-...]
    I -->|POST /api/archive/redeem with JWT & Ticket| J[Server-Side Vault Flag: KCTF{...}]
```

---

## 4. Stage Dependency Matrix

| Stage | Domain | Player Discovery | Prerequisite Input | Bypass Prevention / Security Boundary | Author Test Suite Proof |
|---|---|---|---|---|---|
| **1** | **Web** | Presigned HMAC validation on first parameter; storage handler on last parameter; restricted filename `seal11-relay-telemetry.pcap`. | Public web portal, diagnostic manifests list with valid presigned MACs. | Direct requests to `seal11-relay-telemetry.pcap` return 403 Forbidden. Only pairing a valid manifest MAC with parameter pollution bypasses the gateway. | `tests/test_web_exploit.py` |
| **2** | **Forensics** | Framed `KRP/1.1` protocol over TCP port 9111; target key `relay-seal-eleven`; target public key $Q$; case ID `CASE-KURUKSHETRA-SEAL11`; segmented message chunks. | PCAP artifact retrieved from Stage 1. | Missing the PCAP prevents knowing the protocol framing, target public key, messages, or signatures. | `tests/test_forensics_pcap.py` |
| **3** | **Cryptography** | Recovery of private key $d = \text{0x51f0...}$ via nonce-reuse; forging valid ES256 JWT for Oracle with scope `case:reconcile`. | Genuine signature pair $(r, s_1), (r, s_2)$ and messages $m_1, m_2$ from Stage 2; domain-separated digest spec from `diagnostic-pub-02`. | Oracle endpoint `/api/oracle/query` validates ES256 signatures against $Q$. Invalid, missing scope, or expired tokens return 401 Unauthorized. | `tests/test_crypto_recovery.py`, `tests/test_jwt_auth.py` |
| **4** | **LLM / Agent Security** | Classified memo `#REC-SEAL11-9924` containing indirect prompt injection override; two-phase tool sequence (`reconcile_ledger_state` + `prepare_archive_export reviewer_approved=true`). | Valid ES256 JWT from Stage 3; target case ID. | System prompt policy strictly denies direct unseal requests. Tool requires prior ledger reconciliation, `reviewer_approved=True`, and correct case/archive binding. Flag is never in prompt or model context. | `tests/test_agent_injection.py` |
| **5** | **Flag Delivery** | Unsealed final flag `KCTF{5h4nkh4_51l3n7_3l3v3n7h_534l_3cd54_n0nc3_unl0ck3d_48f9}`. | Valid single-use ticket from Stage 4; valid JWT session. | Server-side vault deletes ticket on first use; enforces case binding; random tickets return 400/404; replayed tickets fail immediately. | `tests/test_ticket_redemption.py` |

---

## 5. Design Rationale & Time Budget Engineering

### Estimated Breakdown for Experienced Players (60–90 min)
1. **Web (10–15 min)**:
   - Identify diagnostic list and notice restricted PCAP in UI and API responses.
   - Test `/api/diagnostics/download` and discover HTTP Parameter Pollution discrepancy (`ref=diagnostic-pub-01&ref=seal11-relay-telemetry.pcap`).
2. **Forensics (15–20 min)**:
   - Open PCAP in Wireshark/tshark/Scapy. Reassemble TCP payload on port 9111.
   - Deconstruct `KRP/1.1` framing (`KRP\x01` + 4-byte length prefix).
   - Filter through 4 key announces and 6 transactions. Triage decoys:
     - Reject `relay-sec-alpha` (different nonce).
     - Reject `relay-sec-beta` (cross-key artificial $r$ duplicate).
     - Reject `relay-sec-gamma` (retransmission replay, identical $m$).
     - Isolate genuine pair under `relay-seal-eleven` where message 2 was segmented across TCP packets.
3. **Cryptography (20–25 min)**:
   - Reconstruct canonical JSON for message 1 (`seq: 108`) and message 2 (`seq: 142`) and compute SHA-256 digests $z_1, z_2$.
   - Apply ECDSA nonce-reuse formula $k = \frac{z_1 - z_2}{s_1 - s_2} \pmod n$.
   - Handle Low-$S$ signature normalization by testing sign permutations $(\pm s_1, \pm s_2) \pmod n$.
   - Verify recovered private key against target public key $Q$.
   - Query `/api/oracle/auth-spec` to observe JWT requirements and mint valid ES256 token.
4. **LLM / Agent Security & Vault (15–25 min)**:
   - Authenticate to `/api/oracle/query`.
   - Observe rejection on direct unseal commands.
   - Query incident reconciliation records for `CASE-KURUKSHETRA-SEAL11`.
   - Oracle RAG fetches `REC-SEAL11-9924`. The indirect injection triggers tool execution `prepare_archive_export(...)` with `reviewer_approved=true`.
   - Receive `TICKET-SEAL11-...` and submit to `/api/archive/redeem` to capture the flag.

---

## 6. Known Risks & Architectural Mitigations

1. **Risk: Model Non-Determinism or Flakiness**:
   - *Mitigation*: The agent architecture provides a deterministic, rule-based CTF adapter that accurately implements RAG retrieval, context loading, indirect prompt injection trigger analysis, and structured tool invocation without external API dependency. An OpenAI API adapter is also supported if configured.
2. **Risk: Accidental Secret Leakage**:
   - *Mitigation*: The flag is stored only on the server and is only returned by `/api/archive/redeem`. Automated hygiene tests (`test_hygiene.py`) verify zero secret leakage in player packages, static assets, templates, or agent prompts.
3. **Risk: Cryptographic Ambiguity**:
   - *Mitigation*: Protocol specifications in public diagnostic `diagnostic-pub-02` explicitly state: curve is P-256, hash is SHA-256, canonical JSON has sorted compact keys, and Low-$S$ normalization is enforced. The public key is provided in the PCAP key exchange announce.
