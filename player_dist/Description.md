# The Silent Conch: The Eleventh Seal

**Category:** Web / Forensics / Crypto / LLM Security  
**Difficulty:** Extra Hard / Insane  
**Flag Format:** `KCTF{...}`  

---

### Description

> *The Eleventh Seal was opened during the night watch, but no commander admits issuing the order.*  
> *The relay's signature records appear authentic, and the Oracle denies any breach of protocol.*  
> *Investigate the available records, reconstruct the sequence of events, and determine how the sealed archive was released.*

During the eleventh day of the Kurukshetra war, perimeter telemetry relays registered an anomalous unseal event. The sacred war chronicle sealed under Wartime Protocol 11 has been released, but the High Command claims that no officer authorized its dissemination.

The Kurukshetra Relay Command & Intelligence Gateway is online. Access the portal, investigate the perimeter telemetry records, uncover the mathematical anomaly, authenticate to the Oracle Assistant, and determine how authority was delegated.

---

### Challenge Entry Point & Connection

- **Web Gateway URL:** `http://<TARGET_HOST>:<TARGET_PORT>/`
- **Protocol:** HTTP REST & Web Portal UI

---

### Available Public Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Kurukshetra Relay Command Dashboard |
| `GET` | `/api/diagnostics/list` | List perimeter diagnostic manifests & telemetry archives |
| `GET` | `/api/diagnostics/view?ref=<id>` | View diagnostic manifest metadata |
| `GET` | `/api/diagnostics/download?ref=<id>` | Download diagnostic manifests or telemetry captures |
| `GET` | `/api/oracle/auth-spec` | Oracle Assistant ES256 JWT specification |
| `POST` | `/api/oracle/query` | Authenticated Oracle Assistant inquiry (Requires ES256 Bearer JWT) |
| `POST` | `/api/archive/redeem` | Archive Vault Redemption Gateway (Requires ES256 Bearer JWT + Single-Use Ticket) |

---

### Rules of Engagement
- All required vulnerabilities are intentionally built into the challenge portal and its cryptographic services.
- No brute-force attacks against network ports, file paths, or cryptographic keys are necessary.
- External LLM accounts, paid APIs, or third-party web credentials are not required.
