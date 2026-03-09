# Security Review

Integration: Proxmox
Repository: https://github.com/ceilingduster/orcorus-proxmox
Commit: latest
Scan Date: 2026-03-09 02:05 UTC

## Security Score

84 / 100

## Tier Classification

Silver

## OWASP Alignment

### OWASP Rubric
- Standard: OWASP Top 10 (2021) aligned review
- Core methodology: architecture context, trust boundaries, data-flow tracing, threat modeling, control verification, and evidence-backed validation
- Key characteristics considered: exploitability, impact, likelihood, attacker preconditions, and business context

### OWASP Security Category Mapping
- A01 Broken Access Control: none
- A02 Cryptographic Failures: none
- A03 Injection: none
- A04 Insecure Design: none
- A05 Security Misconfiguration: none
- A06 Vulnerable and Outdated Components: none
- A07 Identification and Authentication Failures: none
- A08 Software and Data Integrity Failures: none
- A09 Security Logging and Monitoring Failures: none
- A10 Server-Side Request Forgery: none

## Static Analysis Findings (Bandit)

### High Severity
None

### Medium Severity
None

### Low Severity
- Try, Except, Pass detected. in server.py:278 (confidence: HIGH)


## Build Status
SKIPPED

Build step was skipped to avoid running untrusted build commands by default.


## Tests
Detected (pytest)

## Documentation
README: Present
Dependency file: Present

## AI Security Review

# Security Review Report — Proxmox MCP Integration

## 1. OWASP Review Methodology Applied
I applied an OWASP-aligned review process by:
- **Establishing architecture/context**: identified `server.py` as the only runtime entry point, with STDIO-based MCP exposure to an LLM host and outbound HTTPS calls to the Proxmox API using an API token from environment variables.
- **Identifying trust boundaries and entry points**: untrusted input enters via MCP tool arguments and environment variables (`HOST`, `PORT`, `API_TOKEN`, `VERIFY_SSL`, `TIMEOUT_S`).
- **Tracing data flows**: followed tool inputs through validators (`_vnode`, `_vvmid`, `_vpath`, `_vcmd`, `_vupid`) into `_get/_post/_post_json/_delete`, then into Proxmox API paths such as guest-agent exec/file APIs.
- **Modeling threats**: focused on injection, broken access control/delegation, TLS handling, sensitive data exposure, and high-impact VM/container management actions.
- **Verifying controls**: checked input validation, use of JSON-array commands, file path checks, container hardening, and dependency pinning.
- **Validating findings with code evidence**: findings below include concrete file and line references.

## 2. OWASP Top 10 Category Mapping
- **Finding 1**: A02 Cryptographic Failures, A05 Security Misconfiguration
- **Finding 2**: A04 Insecure Design, A01 Broken Access Control
- **Finding 3**: A09 Security Logging and Monitoring Failures

## 3. Critical Vulnerabilities
**None confirmed in the repository code itself**.

Notes:
- The project intentionally exposes high-impact capabilities like VM/container power operations, guest-agent command execution, and guest file read/write. Those are not code-execution bugs in this server; they are the server’s intended administrative function. I did **not** classify that as RCE/injection because commands are passed as structured arrays and forwarded to the Proxmox guest agent without shell invocation.

## 4. High Severity Issues

### Finding 1: TLS certificate verification is disabled by default for Proxmox API communication
- **Severity**: High
- **OWASP**: A02 Cryptographic Failures, A05 Security Misconfiguration
- **File**: `server.py:67`, `server.py:187`
- **Evidence**:
  - `server.py:67` — `self.verify_ssl: bool = os.getenv("VERIFY_SSL", "0") == "1"`
  - `server.py:187` — `verify=cfg.verify_ssl`
- **Why this matters**: The MCP server authenticates to Proxmox with a long-lived API token in an `Authorization` header. With TLS verification off by default, any attacker able to intercept network traffic between the MCP container/process and the Proxmox endpoint can impersonate the API server, capture the token, tamper with responses, or induce destructive actions under the token’s privileges.
- **Exploitability**: Moderate to high in shared network, corporate proxy, container overlay, or hostile local network environments.
- **Impact**: High — compromise of the Proxmox API token can grant broad administrative control over VMs, containers, snapshots, storage visibility, and guest-agent actions.
- **Likelihood**: Medium.
- **Attacker preconditions**: Network position for MITM or traffic interception; victim using default `VERIFY_SSL=0`.
- **Remediation**:
  - Change the default to verification **enabled**.
  - Require an explicit opt-out only for development, ideally guarded by a second strong acknowledgement env var or startup warning.
  - Support custom CA bundles if self-signed/private PKI deployments are expected.
  - Example: change `os.getenv("VERIFY_SSL", "0") == "1"` to default `"1"`, and document how to provide CA trust instead of disabling verification.

### Finding 2: No application-layer authorization or capability scoping for destructive/admin tools
- **Severity**: High
- **OWASP**: A04 Insecure Design, A01 Broken Access Control
- **Files**: `server.py:1019-1360`, especially destructive/admin handlers such as:
  - `server.py:1094-1124` VM power operations
  - `server.py:1134-1151` VM snapshot create/rollback/delete
  - `server.py:1193-1238` guest-agent command execution
  - `server.py:1240-1268` guest file read/write
  - `server.py:1283-1317` container start/stop/reboot/snapshot
- **Evidence**:
  - The MCP `call_tool` handler forwards any exposed tool invocation to `_handle_tool(...)` with no in-process authorization checks beyond parameter validation.
  - `server.py:1369-1378` accepts requested tool name and arguments and returns execution results.
- **Why this matters**: This server is intended to be connected to an MCP-capable client/agent. Once connected, **every exposed tool is callable**. There is no internal role separation such as read-only vs. mutating vs. guest-agent exec/file-write. In practice, this means any principal able to invoke the MCP server inherits the full privilege set of the configured Proxmox API token.
- **Exploitability**: High if the MCP client, host agent, prompt chain, or surrounding orchestration can be influenced by an attacker or an over-permissive user.
- **Impact**: High — arbitrary VM/container stop/start/reset, snapshot rollback, file writes in guests, and guest command execution where the QEMU guest agent is enabled.
- **Likelihood**: Medium to high in real MCP deployments because tool invocation is the core interface and LLM-mediated delegation is a known trust-boundary risk.
- **Attacker preconditions**: Ability to trigger MCP tool calls through the connected client/agent or compromise the upstream LLM/application.
- **Remediation**:
  - Add **tool-level capability gating** in `server.py` before dispatch, e.g. allowlists controlled by env/config such as `ALLOW_MUTATING_TOOLS=0`, `ALLOW_GUEST_EXEC=0`, `ALLOW_GUEST_FILE_WRITE=0`.
  - Split this integration into **read-only** and **admin** profiles or separate servers.
  - Enforce least privilege on the Proxmox API token itself, but do not rely on token scoping alone; add in-server policy checks.
  - Consider confirmation or dual-control wrappers for especially dangerous actions like rollback, stop/reset, exec, and file-write.

## 5. Medium Severity Issues

### Finding 3: Minimal security logging for sensitive administrative actions
- **Severity**: Medium
- **OWASP**: A09 Security Logging and Monitoring Failures
- **Files**: `server.py:29-33`, `server.py:208-249`, `server.py:1369-1378`
- **Evidence**:
  - Logging is configured globally at warning level only: `server.py:29-33`.
  - Tool invocations are not audit-logged at dispatch time.
  - Only transport failures are logged, e.g. `logger.warning("GET %s failed: %s", path, exc)` and similar for POST/DELETE.
- **Why this matters**: The server exposes highly sensitive operations, but there is no audit trail of who/what requested a VM stop, guest command execution, snapshot rollback, or guest file write. In MCP environments, post-incident attribution and review are especially important.
- **Exploitability**: This is not directly exploitable as an attack primitive, but it materially increases dwell time and reduces forensic visibility.
- **Impact**: Medium.
- **Likelihood**: High as an operational deficiency.
- **Attacker preconditions**: None.
- **Remediation**:
  - Add structured audit logs for each tool call with timestamp, tool name, target node/vmid/storage/pool, and whether it was mutating.
  - Avoid logging secrets or full file contents/stdin values.
  - Record failure/success outcomes and relevant Proxmox task IDs/UPIDs.
  - If integrated into a larger platform, forward audit events to centralized logging.

## 6. Low Severity Issues

### Finding 4: Broad exception suppression in base64 decode helper reduces diagnosability
- **Severity**: Low
- **OWASP**: A09 Security Logging and Monitoring Failures
- **File**: `server.py:271-279`
- **Evidence**:
  - `_try_b64_decode()` catches all exceptions and silently `pass`es before returning the original value.
- **Why this matters**: This does not appear directly exploitable, but it can hide malformed/hostile data conditions and makes troubleshooting harder.
- **Remediation**:
  - Catch specific exceptions (`binascii.Error`, `UnicodeDecodeError`) and optionally log at debug level.

## 7. Key Risk Characteristics
- **Primary attack surface**: MCP tool arguments and environment-based endpoint configuration.
- **Most important trust boundary**: the gap between the MCP client/LLM host and the Proxmox administrative API.
- **Exploitability**:
  - TLS issue: requires network position.
  - Authorization/design issue: requires access to trigger MCP tools, which is realistic in agentic integrations.
- **Impact**: High due to infrastructure administration scope.
- **Likelihood**: Medium overall; high in loosely governed MCP/LLM deployments.
- **Required attacker preconditions**:
  - For Finding 1: MITM/network interception plus insecure default config.
  - For Finding 2: ability to invoke or influence MCP tool calls.
  - For Finding 3/4: none; these are defensive gaps.

## 8. Positive Security Practices
- **Good input validation** on node names, VMIDs, snapshot names, UPIDs, command arrays, and file paths (`server.py:102-173`).
- **Command execution avoids shell injection** by requiring a JSON array of strings rather than a shell command string (`server.py:153-173`, `server.py:1193-1204`, `server.py:1220-1233`).
- **Guest file path constraints** require absolute paths, reject null bytes, and reject `..` traversal segments (`server.py:141-151`).
- **Input size limits** exist for stdin/content and command length/count (`server.py:98-100`, `server.py:1197-1203`, `server.py:1225-1231`, `server.py:1258-1264`).
- **Container hardening**: Dockerfile uses a non-root user (`Dockerfile:4`, `Dockerfile:13`).
- **Pinned dependencies** in the Docker image (`Dockerfile:9-10`) reduce accidental drift.

## 9. Recommendations

### High priority
1. **Enable TLS verification by default**
   - **File**: `server.py:67`, `server.py:187`
   - **Category**: A02, A05
   - **Fix**: Default `VERIFY_SSL` to enabled; support custom CA trust for private PKI.

2. **Add application-layer authorization/capability controls**
   - **File**: `server.py:1019-1360`, `server.py:1369-1378`
   - **Category**: A01, A04
   - **Fix**: Gate tools by policy group before dispatch:
     - read-only
     - mutating VM/container lifecycle
     - guest exec
     - guest file write
     - storage/pool administration
   - Expose only the minimum necessary tools for each deployment profile.

### Medium priority
3. **Implement structured audit logging for all administrative actions**
   - **File**: `server.py:29-33`, `server.py:1369-1378`
   - **Category**: A09
   - **Fix**: Log tool name, target identifiers, caller/session context if available, outcome, and UPID/task IDs; redact secrets and payload bodies.

### Low priority
4. **Tighten broad exception handling in `_try_b64_decode`**
   - **File**: `server.py:271-279`
   - **Category**: A09
   - **Fix**: Catch specific exceptions and optionally emit debug telemetry.

## 10. Next Tier Upgrade Plan
- **Likely current tier**: **Bronze**
  - Reason: strong basic validation and safe command formatting are present, but there is an unsafe TLS default and no in-server policy separation for dangerous tools.
- **Next target tier**: **Silver**
- **Concrete prioritized actions to reach Silver**:
  1. **Flip TLS verification to secure-by-default** and document trust-store configuration for self-signed certs.
  2. **Introduce capability-based tool gating** with separate read-only/admin/guest-agent profiles.
  3. **Add structured audit logs** for all tool invocations and results.
  4. **Document least-privilege token requirements** for the Proxmox API token and provide deployment examples for reduced-scope roles.
  5. **Add security tests** covering invalid input, blocked dangerous tools under restricted profiles, and TLS-default behavior.

---

## Final Assessment
The codebase is generally careful about direct injection risks and validates most user-controlled parameters well. The main security concerns are **deployment/design-level**: an insecure default for TLS verification and the absence of **application-layer restriction** around highly privileged infrastructure actions. These are real and material issues for an MCP integration because the surrounding client/agent trust boundary is frequently weaker than a traditional manually operated admin console.

## Summary

Security Score: 84/100 (Silver)
Static analysis found 0 high, 0 medium, and 1 low severity issues.
Build step skipped for safety.
Tests detected.
