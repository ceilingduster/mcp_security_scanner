# SSH Command MCP Integration

Execute commands on remote hosts over SSH.

- **Image:** `orcorus/ssh-command`
- **Transport:** STDIO
- **Tools:** 1

## Tool

### `ssh_exec`

Execute a command on a remote host via SSH.

| Argument | Type | Required | Description |
|---|---|---|---|
| `command` | string | yes | Command to run remotely |
| `host` | string | no | Target host (overrides `SSH_HOST` env) |
| `port` | integer | no | SSH port (overrides `SSH_PORT` env) |
| `username` | string | no | Login user (overrides `SSH_USERNAME` env) |
| `password` | string | no | Password auth (overrides `SSH_PASSWORD` env) |
| `private_key` | string | no | SSH private key content (overrides `SSH_PRIVATE_KEY` env) |
| `passphrase` | string | no | Passphrase for encrypted private key (overrides `SSH_PRIVATE_KEY_PASSPHRASE` env) |

All optional arguments fall back to their corresponding environment variable when not provided.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SSH_HOST` | `localhost` | Target host |
| `SSH_PORT` | `22` | SSH port |
| `SSH_USERNAME` | `root` | Login user |
| `SSH_PASSWORD` | | Password auth (used when no key is provided) |
| `SSH_PRIVATE_KEY` | | Private key content (OpenSSH, PEM, Ed25519, ECDSA, RSA, DSA) |
| `SSH_PRIVATE_KEY_PASSPHRASE` | | Passphrase for encrypted keys |

If both password and private key are provided, private key authentication takes priority.

## Running with Docker

```bash
docker run --rm -i \
  -e SSH_HOST=myserver.example.com \
  -e SSH_PORT=22 \
  -e SSH_USERNAME=deploy \
  -e SSH_PRIVATE_KEY="$(cat ~/.ssh/id_ed25519)" \
  orcorus/ssh-command
```

## Key Format Support

Uses `asyncssh` which natively supports all common SSH key formats including OpenSSH-format keys that paramiko struggles with.

## Security

- The container runs as a non-root user (`mcp`).
- Host key checking is disabled (`known_hosts=None`) — equivalent to `StrictHostKeyChecking=no`.
- Command timeout: 30 seconds.

## Runtime

- Base image: `python:3.12-slim`
- Dependencies: `asyncssh==2.22.0`, `fastmcp==2.3.4`
