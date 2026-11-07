# Security Assessment

## Vulnerability & Exposure Analysis (Prior to Patching)

This document presents a security assessment of the potential vulnerability exposure and exploit capability regarding the application prior to upgrading Node.js to release 26 (and patching bundled dependencies).

### 1. CVE-2026-111497: Brotli Decoder RCE ("Node2Shell")
* **Severity**: CVSS 4.0 Score 9.2 Critical (Node.js advisory rated High).
* **Flaw Description**: An out-of-bounds write flaw in the bundled Brotli decoder library integrated with Node.js.
* **Attack Vector & Reachability**:
  - The flaw is triggered when processing malformed or specifically crafted compressed input using the Brotli decoder.
  - In server application environments, reachability typically requires accepting user-supplied Brotli-compressed HTTP request bodies or processing remote response content via client fetch/HTTP request mechanisms using Brotli decompression.
* **Assessment for this Application**:
  - Prior to patching, this repository served as a static client application bundled with Parcel and served via static web servers (such as GitHub Pages or `serve` in Docker).
  - The static front-end assets do not process unauthenticated remote compressed streams or handle server-side decompression of incoming request payloads.
  - While the underlying Node.js runtime vulnerable image (`node:20-slim`, etc.) contained the affected Brotli C-library code, the application code itself did not expose endpoint handlers or decompression pipeline triggers that accept untrusted Brotli input.
  - **Exploit Capability**: Low/Unlikely exposure in runtime static deployment, but remediated fully by upgrading Node.js to 26.x.

### 2. TLS Hostname & Certificate Bypasses (CVE-2026-105483 & CVE-2026-106069)
* **Flaw Description**: Issues in TLS hostname validation logic where hostnames with fullwidth digits or hostnames that resolve loosely to IP addresses bypass proper certificate validation.
* **Impact & Exposure**:
  - Potential Man-In-The-Middle (MITM) attacks if outbound TLS connections are made to malicious or attacker-controlled hosts using manipulated hostname strings.
  - For this client build pipeline, static asset generation occurs at build time. Outbound runtime TLS calls are made directly by user browser environments rather than Node.js backend services.
  - **Exploit Capability**: Low exposure for static client runtime; resolved by Node.js 26 update.

### 3. DNS Truncation Handling Issue (CVE-2026-105482)
* **Flaw Description**: `dns.resolve` truncates hostnames containing `NUL` characters, leading to incomplete string validation bypasses.
* **Impact & Exposure**:
  - Can allow SSRF defense evasion or unexpected hostname resolution when user-supplied hostnames are validated prior to resolution.
  - **Exploit Capability**: None in this static frontend application, as Node's `dns` module is not exposed or used to resolve user-supplied input dynamically.

---

## Defensive Mitigation & Resolution
Upgrading to Node.js 26 release and updating all npm dependencies ensures that:
1. The bundled Brotli C-library is updated with memory safety bounds checks.
2. TLS hostname validation logic correctly handles fullwidth characters and loose IP resolutions.
3. DNS resolution functions strictly handle string inputs without truncation on `NUL` bytes.
