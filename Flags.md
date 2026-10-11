# The Silent Conch: The Eleventh Seal - Flags & Validation Data

## Canonical Flag
```
KCTF{5h4nkh4_51l3n7_3l3v3n7h_534l_3cd54_n0nc3_unl0ck3d_48f9}
```

## Validation & Cryptographic Constants (Author-Only)
- **Curve**: NIST P-256 (`secp256r1`)
- **Curve Order $n$**: `0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551`
- **Target Key ID (`kid`)**: `relay-seal-eleven`
- **Target Case Binding**: `CASE-KURUKSHETRA-SEAL11`
- **Target Archive Identifier**: `ARCHIVE-SEAL-11`

### Target Keypair
- **Target Private Key ($d$)**:
  - Hex: `0x51f0f34cf2235b4d9292e6cfda0cb4d091ec494c329c34406fd6d073e394d76d`
  - Int: `37066922937397759812420794563855584550882255747683145459341498675685519775597`
- **Target Public Key Coordinates**:
  - $Q_x$: `0xff6641aa230347b47490ebc56ffd971602d98a5925c7cf2b21d7ab1eba970ad0`
  - $Q_y$: `0xc1fb0891d4928c9165926477c0fb32e9552541063a1833891af95ad1e14db091`
  - SEC1 Uncompressed Hex: `04ff6641aa230347b47490ebc56ffd971602d98a5925c7cf2b21d7ab1eba970ad0c1fb0891d4928c9165926477c0fb32e9552541063a1833891af95ad1e14db091`

### Reused Ephemeral Nonce ($k$)
- **Nonce ($k$)**:
  - Hex: `0x7a3f81b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1`
- **Signature $r$**:
  - Hex: `0x2f03d8b4d9c339d0af6017e58d026db64c1e7f94c8ecc3309e043dc8e558939f`

### Genuine Signed Messages
1. **Message 1 (`seq`: 108)**:
   - Content: `{"action":"SEAL_TELEMETRY_LOG_1","case_id":"CASE-KURUKSHETRA-SEAL11","payload":{"flux":412,"sensor":"GATE_NORTH","status":"LOCKED"},"seq":108,"timestamp":1718064120}`
   - Digest $z_1$: `0x865ed3e4b4f12f45dfd5d2611c04a394a4ca6c2adf049d0015a4f9cd1b839003`
   - Signature $s_1$: `0x7da36ff1a98ae742ad1ffdabbcedbd04841057d18961275a0241dd3dff15977e` (Low-S canonicalized)
2. **Message 2 (`seq`: 142)**:
   - Content: `{"action":"SEAL_DISPATCH_RECORD_2","case_id":"CASE-KURUKSHETRA-SEAL11","payload":{"alert":"NIGHT_WATCH_SHADOW","cleared":false,"origin":"OUTPOST_9"},"seq":142,"timestamp":1718064380}`
   - Digest $z_2$: `0xf46671497dfc54f1034c552677f04765ee699d619e09af370d93da14633a66c1`
   - Signature $s_2$: `0xfee7744ea18df58c346c8bb4d0de8ab1d144136a3ddaebe465577345549a8d83` (High-S, $s_2 > n/2$)

### Redemption Mechanism
The flag is served exclusively by `POST /api/archive/redeem` when supplied with:
1. A valid ES256 Bearer JWT signed with the target private key.
2. An unredeemed, non-expired single-use ticket issued by the Oracle's `prepare_archive_export` tool.
3. Correct `case_id: "CASE-KURUKSHETRA-SEAL11"`.
