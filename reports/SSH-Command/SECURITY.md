# Security Review

Integration: SSH-Command
Repository: /srv/docker/orcorus-integrations/ssh-command
Commit: local
Scan Date: 2026-03-09 03:48 UTC

## Security Score

75 / 100

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
None


## Build Status
SKIPPED

Build step was skipped to avoid running untrusted build commands by default.


## Tests
Not detected

## Documentation
README: Present
Dependency file: Missing

## AI Security Review

OWASP-ALIGNED SECURITY REVIEW

Repository: SSH-Command
Files reviewed: server.py, Dockerfile, README.md

1) OWASP Review Methodology Applied
- Architecture & Context: I inspected entry points (server.py), the Dockerfile, and README to understand how the MCP exposes capabilities, how it is run, and default configuration.
- Trust Boundaries & Entry Points: Identified external inputs (MCP tool arguments, environment variables, STDIO transport) and external network boundaries (asyncssh.connect to target SSH hosts).
- Data Flows: Traced how user-supplied values (command, host, credentials) flow into _build_connect_kwargs and into asyncssh.connect/conn.run.
- Threat Modeling: Identified misuse and abuse cases: remote command execution abuse, man-in-the-middle (MITM) on SSH, server-assisted access to internal networks, credential exposure, and inadequate logging/auditing.
- Controls Verification: Checked for cryptographic checks (host key verification), input validation, authentication/authorization controls, secret handling, and dependency management.
- Validation / Evidence: All findings reference concrete lines in server.py and Dockerfile and indicate severity and remediation.

2) OWASP Top 10 Mapping (2021)
- A01 Broken Access Control: related to lack of caller authorization — tool allows arbitrary commands and connection targets.
- A02 Cryptographic Failures: host key checking disabled (known_hosts=None) → MITM risk.
- A03 Injection: user-supplied 'command' is executed on target host without any filtering or policy.
- A05 Security Misconfiguration: insecure defaults (SSH_USERNAME default root), host key verification disabled, permissive Dockerfile information mismatch in README.
- A06 Vulnerable and Outdated Components: pinned dependencies require CVE monitoring.
- A07 Identification and Authentication Failures: weak defaults and lack of authentication/authorization of callers; potential leakage of env credentials to callers.
- A09 Security Logging and Monitoring Failures: no audit or persistent logging of commands, callers, or outcomes.
- A10 Server-Side Request Forgery (SSRF): the service can be instructed to connect to arbitrary internal hosts/ports and run commands.

3) Critical Vulnerabilities
No immediate arbitrary code execution (RCE) on the MCP host itself was found — the code intentionally executes commands on remote systems via SSH. However the following are critical in the sense of enabling remote network abuse / arbitrary remote command execution (on target hosts):

Finding: Unrestricted remote command execution on arbitrary hosts (high-risk remote abuse)
- File: server.py
- Lines: ssh_exec signature (server.py:53) and execution (server.py:78-79)
  - Evidence: The 'ssh_exec' tool takes a free-form 'command' string from the caller and passes it directly to conn.run(command) (server.py:78-79). There is no validation, allowlist, or authorization enforced by this code.
- Severity: Critical (for target hosts) / High (for MCP host exposure)
- Impact: An attacker who can invoke the MCP tool can run arbitrary commands on any host reachable from the container using supplied credentials or the container's environment credentials. This can be used to pivot into internal networks, access sensitive systems, or execute destructive commands on targets.
- Exploitability: High if attacker can call this tool (MCP caller with runtime access). No special preconditions beyond ability to call the tool.
- Remediation: Add strict authorization and usage policies before allowing invocation. Implement one or more of:
  - Enforce a host allowlist/CIDR allowlist (environment-configurable) and validate 'host' against it. (Modify server.py: _build_connect_kwargs host handling, validate host before using.)
  - Enforce a command allowlist or templated commands (only allow pre-approved scripts/operations). If free-form commands are required, restrict who can call the tool.
  - Add per-call authentication and RBAC so only trusted principals can use this tool.

Note: This behavior is the primary purpose of the integration; the security control must be applied outside or within the MCP to restrict who may call it.

4) High Severity Issues

4.1 Host key verification disabled – MITM risk (Cryptographic Failures, A02)
- File: server.py
- Line: opts definition - known_hosts: None (server.py:31-32)
  - Evidence: known_hosts is set to None in _build_connect_kwargs; README explicitly states "Host key checking is disabled (known_hosts=None) — equivalent to StrictHostKeyChecking=no."
- Severity: High
- Impact: Enables man-in-the-middle attacks. An attacker controlling network paths or DNS could MITM the SSH session, capture credentials (passwords, keys) or modify commands/responses.
- Exploitability: Moderate to high when attacker can intercept network traffic between the container and target or if the tool is able to reach attacker-controlled hosts.
- Remediation:
  - Prefer enabling host key verification. Provide a mechanism to supply known_hosts (file path or content) or fingerprint validation per-host (configuration and per-call fingerprint parameter). Implement known_hosts handling in _build_connect_kwargs rather than forcing None.
  - If TOFU (Trust-On-First-Use) is required, make it opt-in and log the first-seen host key fingerprint for operator approval.
  - Code change: replace "known_hosts": None with param to accept known_hosts path or known_host_fingerprint; use asyncssh.connect(known_hosts=path) or known_hosts param as provided.
  - Files/lines: server.py:29-33.

4.2 Server-side network/access proxying (SSRF-like) – arbitrary host/port (A10)
- File: server.py
- Lines: host/port selection in _build_connect_kwargs (server.py:29-31) and usage in ssh_exec (server.py:53)
- Evidence: Caller can override 'host' and 'port' to cause outbound SSH connections from the MCP container to anywhere the container can reach.
- Severity: High
- Impact: Attackers can use this service as a pivot point to access internal-only systems or cloud metadata endpoints, perform lateral movement, or exfiltrate data.
- Exploitability: High if invocation is possible from attacker-controlled model/tooling. Low otherwise.
- Remediation:
  - Implement allowlist/denylist for hosts and ports. Validate against CIDR ranges and hostnames.
  - Optional: Restrict to preconfigured SSH_HOST only; remove per-call override or require operator approval for new targets.
  - Files/lines: server.py:29-33 and ssh_exec signature (server.py:53).

4.3 Sensitive secrets in environment and per-call arguments (A02/A07)
- File: server.py
- Lines: SSH_* env read (server.py:11-16), private key handling (server.py:35-45)
- Evidence: SSH_PRIVATE_KEY and SSH_PASSWORD can be set as env and will be used for connections. The tool also accepts private_key and passphrase as tool parameters, allowing callers to supply secrets.
- Severity: High
- Impact: Secrets may be exposed to multiple callers of the same MCP instance; they could be accidentally logged by the caller or returned in error messages; using environment variables makes secret lifecycle management harder.
- Exploitability: Moderate — depends on caller isolation and how operators configure env.
- Remediation:
  - Encourage use of secret storage systems (vault) and avoid embedding secrets directly in env variables where callers share the MCP instance.
  - If per-call private_key is allowed, only accept it from authenticated/trusted callers; consider disabling the env-based global SSH_PRIVATE_KEY by default.
  - Ensure exception messages do not echo secrets: the ValueError raised on SSH key error (server.py:62) may reveal details. Avoid including raw exception text that can contain sensitive info.
  - Files/lines: server.py:11-16, server.py:35-45, server.py:60-63.

5) Medium Severity Issues

5.1 Default username 'root' (Security Misconfiguration, A05)
- File: server.py
- Lines: SSH_USERNAME default (server.py:13)
- Evidence: SSH_USERNAME defaults to 'root'. This encourages use of the highest-privilege account and increases blast radius.
- Severity: Medium
- Impact: If used, successful authentication will have root privileges on target hosts which is more destructive than a limited user.
- Remediation: Change default to an empty value or a low-privilege default user, and require explicit configuration. Document that root should be avoided.

5.2 No auditing/command logging (A09)
- File: server.py
- Lines: ssh_exec body (server.py:53-81)
- Evidence: No logging or persistent audit of who invoked the tool, what command ran, to which host, or command outputs (only returned to caller). README mentions only timeout and run user.
- Severity: Medium
- Impact: Difficult to detect or investigate abuse; non-repudiation lacking.
- Remediation: Implement structured logging of requests (caller identity if available), target host, sanitized command (or full command with authorization), start/end timestamps, exit codes, and optionally hashes of outputs. Ensure logs are sent to a secure logging system and sensitive outputs are redacted.

5.3 Error handling may leak details (A02/A07)
- File: server.py
- Lines: try/except around _build_connect_kwargs (server.py:60-63), return of stderr/stdout (server.py:80-85)
- Evidence: Exceptions from asyncssh.import_private_key are wrapped and included in the ValueError: "SSH key error: {e}". The exception text might include detailed internal failure reasons.
- Severity: Medium
- Impact: Information disclosure leads to easier reconnaissance by attackers.
- Remediation: Replace error messages with generic text and log full exception details to secure operator logs only. Avoid returning raw stderr/stderr that might contain sensitive content unless caller is authorized.

6) Low Severity Issues

6.1 README and Dockerfile version mismatch
- Files: Dockerfile (pip install fastmcp==3.1.0) vs README (fastmcp==2.3.4)
- Severity: Low
- Remediation: Update README to match Dockerfile or update Dockerfile; ensure pinned versions are declared in a requirements file for easier scanning.

6.2 Returning full stdout/stderr to caller (privacy / exfil risk)
- File: server.py
- Lines: building returned parts (server.py:80-86)
- Severity: Low
- Remediation: Consider limits on output size, explicit redaction options, or return structured results with a maximum size cap.

6.3 No explicit resource limits in Dockerfile
- File: Dockerfile
- Evidence: No runtime resource limits at container level (should be set by orchestration). Dockerfile itself is fine, but recommend runtime constraints.
- Severity: Low
- Remediation: Enforce CPU/memory limits at deployment time.

7) Key Risk Characteristics (summary per major finding)

Unrestricted remote command execution (server.py:53 and 78-79)
- Exploitability: High if the attacker can call the MCP tool
- Impact: Very High on target hosts (full arbitrary command execution). High for the environment indirectly (pivoting, exfiltration).
- Likelihood: Depends on who can call the MCP. If MCP is deployed to be driven by untrusted models, likelihood is high.
- Preconditions: Ability to send valid MCP requests (i.e., the model or controller can call the tool); presence of valid credentials or ability to reach target host.

Host key checking disabled (server.py:31-33)
- Exploitability: Moderate
- Impact: High (credentials compromise, MitM)
- Likelihood: Moderate in attacker-in-the-middle scenarios or if DNS is compromised.
- Preconditions: Network path control or ability to influence the target host resolution.

Secrets in env/per-call (server.py:11-16, 35-45)
- Exploitability: Moderate
- Impact: High (compromised credentials allow full SSH access where keys are valid)
- Likelihood: Moderate when multiple callers share the container or attacker can call tool.
- Preconditions: Secrets present and accessible to the process; attacker can call the tool or read process environment.

8) Positive Security Practices
- Container runs as a non-root user (Dockerfile: lines creating "mcp" user and using USER mcp) — good least-privilege runtime practice.
- Command timeout enforced (asyncio.wait_for with timeout=30, server.py:79) to reduce hanging connections and DoS from long-running commands.
- Dependencies explicitly pinned in Dockerfile (good for reproducibility) though they still require monitoring for CVEs.

9) Concrete Recommendations (file:line references) with OWASP Category Context

9.1 Enforce host key verification (A02)
- Files/lines: server.py:29-33 (known_hosts handling)
- Fix: Replace "known_hosts": None with configuration to accept a known_hosts path or fingerprint parameter. Example: read an env var SSH_KNOWN_HOSTS that points to a file or supply a per-call fingerprint argument. Use asyncssh.connect(known_hosts=known_hosts_path) or verify server_host_key separately.
- Rationale: Prevent MITM; require operator provisioning of trusted host keys or fingerprints.

9.2 Add target network allowlist / remove per-call override or require RBAC (A10, A01)
- Files/lines: server.py:29-33 and ssh_exec signature server.py:53
- Fix: Implement an environment-configured allowlist (SSH_ALLOWED_CIDRS, SSH_ALLOWED_HOSTS). Validate host parameter: reject if not in allowlist. If per-call host setting is necessary, require a trusted RBAC token prior to allowing overrides.

9.3 Add authorization/usage controls for callers (A01, A07)
- Files/lines: ssh_exec entry point server.py:53 and mcp.run usage server.py:90
- Fix: Integrate with an authentication/authorization mechanism for callers. At minimum, document that this MCP must only be run in a trusted controller context. Prefer adding an allowlist of caller IDs or require signed requests.

9.4 Avoid storing global secrets in env for shared services; integrate with secret manager (A02, A07)
- Files/lines: server.py:11-16, server.py:35-45
- Fix: Make SSH_PRIVATE_KEY empty by default and require explicit per-call credential retrieval from a secure vault (and require caller authorization). If environment secrets must be used, document strict operational controls and limit container access.

9.5 Implement logging/audit and redact secrets (A09)
- Files/lines: server.py:53-86
- Fix: Log each invocation with timestamp, caller identity, target, and outcome. Store logs in a central secure system with retention policies. Redact or do not include full command outputs in logs unless necessary.

9.6 Harden error handling to avoid leaking internal errors to callers (A02)
- Files/lines: server.py:60-63
- Fix: Replace ValueError(f"SSH key error: {e}") with a generic error returned to caller and log the exception details only to operator logs.

9.7 Add output size limits and redaction (privacy) (A05)
- Files/lines: server.py:80-86
- Fix: Truncate stdout/stderr to a configured maximum length and optionally return a pointer to securely stored full output for authorized operators.

9.8 Dependency management & CVE scanning (A06)
- File: Dockerfile
- Fix: Introduce a requirements.txt with exact versions and run automated vulnerability scanning on images (e.g., Snyk, OSV, GitHub Dependabot). Track upstream asyncssh CVEs and update accordingly.

9.9 Reduce default privileges (A05)
- File: server.py:13
- Fix: Remove default 'root' username; require explicit username or use a low-privilege default.

10) Next Tier Upgrade Plan (Current tier assessment and steps)

Current Tier: Bronze
- Reasoning: Integration works and has some good practices (non-root user, timeout). However, it exposes powerful functionality (remote command execution) with permissive defaults (host key checking disabled, default root, no allowlist or auth), lacks auditing, and allows secret use via environment or per-call arguments. These issues make it unsafe for untrusted callers.

Target Next Tier: Silver
- Goal: Make integration safe for use by trusted controllers and limit misuse for untrusted models.

Prioritized actions to reach Silver (ordered):
1. Enforce host key verification / fingerprint validation (server.py:29-33) — prevents MITM and is one of the highest priority fixes. (OWASP: A02)
2. Implement network target allowlist (SSH_ALLOWED_CIDRS / SSH_ALLOWED_HOSTS) and validate host param (server.py:29-33, server.py:53) — prevents SSRF/pivoting. (OWASP: A10)
3. Add caller authentication/authorization to the MCP runtime or require per-deployment gating so only trusted callers can invoke the tool (server.py:53/mcp.run) (OWASP: A01/A07)
4. Replace environment secret usage with explicit, audited secret retrieval (Vault) and disallow global SSH_PRIVATE_KEY by default (server.py:11-16, 35-45) (OWASP: A02/A07)
5. Add structured logging/audit for calls and outcomes and redact outputs (server.py:53-86) (OWASP: A09)
6. Add input validation and optional command allowlisting or templating for high-risk commands (server.py:53) (OWASP: A03)
7. Add automated dependency CVE scanning and update pinned versions as needed (Dockerfile) (OWASP: A06)

Gold-level (longer term):
- Implement RBAC integrated with operator identity management, mutual TLS for controller connections to the MCP, signed request validation, operator approval workflows for new targets, encrypted-at-rest logs, ephemeral credentials for remote host access, runtime isolation (seccomp, AppArmor), and stricter network egress controls in deployment.

11) Summary of Findings with line-specific remediation

- server.py:11-16 (High)
  - Issue: Secrets (SSH_* env) used; private key can be provided via env. Remediation: Remove default secret env usage for shared instances, integrate secret manager.

- server.py:13 (Medium)
  - Issue: SSH_USERNAME defaults to 'root'. Remediation: Remove default or change to low-priv user.

- server.py:29-33 (High)
  - Issue: known_hosts = None disabling host key verification. Remediation: Accept known_hosts file or host fingerprint and perform verification.

- server.py:35-45 (High)
  - Issue: import_private_key accepts raw private key content from env or caller. Remediation: Require secure secret retrieval and authorize callers; avoid echoing secrets in errors.

- server.py:53, 78-79 (Critical)
  - Issue: ssh_exec accepts free-form command and runs it on arbitrary reachable hosts. Remediation: Restrict callable principals; add host/command allowlists and RBAC.

- server.py:60-63 (Medium)
  - Issue: Error strings may include exception text with sensitive details. Remediation: Log details internally; return sanitized errors to callers.

- server.py:80-86 (Low/Medium)
  - Issue: Returns unbounded stdout/stderr to caller. Remediation: Truncate large output, optionally store full output in secure storage that requires authorization to fetch.

- Dockerfile (Low)
  - Issue: README/documentation mismatch in pinned fastmcp version; no vulnerability scanning. Remediation: Consolidate versioning, add requirement file and integrate CVE scanning.

12) Final notes
- This integration is powerful and purposely executes commands on remote machines. It is safe to include such functionality only when the MCP is deployed in a tightly controlled, trusted environment and when callers are authenticated and authorized. Without these external controls the integration is directly usable as a remote command execution proxy and a potential pivoting tool.
- If this MCP is intended to be published to third-party or untrusted controllers, do not ship it with the current defaults (known_hosts=None, SSH_USERNAME=root, global env secrets). Implement the recommendations above before making it available broadly.

If you want, I can produce a patch set (diff) implementing the highest-priority changes: host key verification support, host allowlist validation, sanitized error handling, and basic invocation logging. 

## Summary

Security Score: 75/100 (Silver)
Static analysis found 0 high, 0 medium, and 0 low severity issues.
Build step skipped for safety.
No automated tests detected.
