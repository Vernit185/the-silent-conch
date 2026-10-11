# Challenge server connection

This repository contains no FastAPI source, confirmed request schemas, or configured server URL. Integration has **not** been verified against the challenge server. No operational records or successful results are simulated.

## Configuration

Set `VITE_API_BASE_URL=https://your-challenge-server.example` before building for a separately hosted FastAPI service. This is a public service URL, not a credential. Leave it unset for same-origin deployments. The frontend uses `/openapi.json` to discover the actual API contracts before enabling controls. The base URL should be the server origin (or mounting prefix), without an appended `/api`.

For same-origin deployment, route `/openapi.json` and `/api/*` to the existing FastAPI application and route frontend pages to this application. No replacement API routes have been introduced here.

For separate hosting, FastAPI must allow the frontend's exact origin, the methods used by declared endpoints and `Authorization` and `Content-Type` headers. Expose `Content-Disposition` if download filenames should be read. Keep backend ticket, authentication, security and challenge behavior unchanged.

## Contract discovery

Only the following example operations are activated when declared by the real OpenAPI document:
- `GET /api/diagnostics/download`
- `POST /api/oracle/query`
- `POST /api/archive/redeem`

Inventory discovery recognizes `GET /api/diagnostics/records` or `GET /api/diagnostics/list` only if present. It does not send requests to invented record endpoints. A returned `records` or `items` array, or a top-level array, can populate the inventory; the complete original response remains inspectable.

Primitive JSON body and query fields, required flags, enums, numeric/string constraints and HTTP bearer authorization come from the server's OpenAPI schema. Unsupported complex schemas or authentication methods disable the operation and require a contract-specific adapter. Servers that hide OpenAPI must provide verified source contracts so this adapter can be replaced; do not guess request fields.

Response reports display all returned fields as text, including retrieved documents, execution details and any server-returned flag. No HTML execution or flag shortcuts exist. Credentials stay in memory and are never logged or stored.

## Verification boundaries

Frontend navigation, missing-contract states, client validation, request construction and text-only response rendering can be tested without a backend. Actual authentication, downloads, successful Oracle queries, ticket rejection/replay and flag release remain unverified until the real server is supplied. Server-side validation remains the responsibility of the unchanged FastAPI backend.
