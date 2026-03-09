# Proxmox VE MCP Server

Manage Proxmox VE clusters — VMs, containers, nodes, storage, and tasks — via the Model Context Protocol.

- **Image:** `orcorus/proxmox:v1.0.0`
- **Transport:** STDIO
- **Tools:** 53

## Configuration

| Variable    | Required | Description                                      | Example                                          |
|-------------|----------|--------------------------------------------------|--------------------------------------------------|
| `HOST`      | yes      | Proxmox hostname or IP address                   | `pve.example.com`                                |
| `PORT`      | yes      | Proxmox API port                                 | `8006`                                           |
| `API_TOKEN` | yes      | PVE API token (secret)                           | `user@realm!tokenid=xxxxxxxx-xxxx-xxxx-xxxx-xxxx` |
| `VERIFY_SSL`| no       | Set to `1` to enable TLS certificate verification | `0`                                              |
| `TIMEOUT_S` | no       | HTTP request timeout in seconds (default: `30`)  | `30`                                             |

### Creating a Proxmox API token

In the Proxmox web UI: **Datacenter > Permissions > API Tokens > Add**

The token format is: `user@realm!tokenid=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

Grant the token the minimum permissions needed for your use case (e.g. `PVEVMAdmin` for VM management).

## Running with Docker

```bash
docker run --rm -i \
  -e HOST=pve.example.com \
  -e PORT=8006 \
  -e API_TOKEN=user@pam!mytoken=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  orcorus/proxmox:v1.0.0
```

## Tools

### Cluster

| Tool | Description |
|------|-------------|
| `proxmox_version` | Get Proxmox VE API version and server build info |
| `proxmox_cluster_status` | Get cluster status, nodes, and quorum |
| `proxmox_cluster_resources` | List all cluster resources (VMs, containers, storage, nodes) |
| `proxmox_cluster_tasks` | List recent cluster-wide tasks |

### Nodes

| Tool | Description |
|------|-------------|
| `proxmox_list_nodes` | List all nodes with status and resource summary |
| `proxmox_node_status` | Get CPU, memory, uptime, and kernel info for a node |
| `proxmox_node_services` | List system services on a node |
| `proxmox_node_rrd` | Get RRD performance time-series data for a node |
| `proxmox_node_tasks` | List recent tasks on a node |

### Tasks

| Tool | Description |
|------|-------------|
| `proxmox_task_status` | Get status of a task by UPID |
| `proxmox_task_log` | Get log output of a task by UPID |
| `proxmox_task_stop` | Stop / cancel a running task |

### VMs (QEMU/KVM)

| Tool | Description |
|------|-------------|
| `proxmox_list_vms` | List all QEMU VMs on a node |
| `proxmox_vm_status` | Get runtime status of a VM (running/stopped, CPU%, mem) |
| `proxmox_vm_config` | Get hardware configuration of a VM |
| `proxmox_vm_start` | Start a stopped VM |
| `proxmox_vm_stop` | Immediately power-off a VM |
| `proxmox_vm_shutdown` | Gracefully shut down a VM via ACPI |
| `proxmox_vm_reboot` | Gracefully reboot a VM |
| `proxmox_vm_reset` | Hard-reset a VM |
| `proxmox_vm_suspend` | Suspend a running VM |
| `proxmox_vm_resume` | Resume a suspended VM |
| `proxmox_vm_snapshot_list` | List snapshots for a VM |
| `proxmox_vm_snapshot_create` | Create a VM snapshot (optionally include RAM state) |
| `proxmox_vm_snapshot_rollback` | Rollback a VM to a snapshot |
| `proxmox_vm_snapshot_delete` | Delete a VM snapshot |
| `proxmox_vm_rrd` | Get RRD performance time-series data for a VM |

### QEMU Guest Agent

These tools require the QEMU guest agent to be installed and running inside the VM.

| Tool | Description |
|------|-------------|
| `proxmox_vm_agent_ping` | Ping the guest agent to verify it is responsive |
| `proxmox_vm_agent_info` | Get guest agent version and supported commands |
| `proxmox_vm_agent_osinfo` | Get OS name, version, and kernel from inside the VM |
| `proxmox_vm_agent_network` | Get network interfaces and IP addresses from inside the VM |
| `proxmox_vm_agent_fsinfo` | Get filesystem mount points and usage from inside the VM |
| `proxmox_vm_exec` | Start a command inside a VM (non-blocking, returns PID) |
| `proxmox_vm_exec_status` | Poll the result of a guest exec by PID |
| `proxmox_vm_exec_sync` | Run a command inside a VM and wait for it to finish |
| `proxmox_vm_file_read` | Read a file from inside a VM via the guest agent |
| `proxmox_vm_file_write` | Write a file inside a VM via the guest agent |

### LXC Containers

| Tool | Description |
|------|-------------|
| `proxmox_list_containers` | List all LXC containers on a node |
| `proxmox_container_status` | Get runtime status of an LXC container |
| `proxmox_container_config` | Get configuration of an LXC container |
| `proxmox_container_start` | Start a stopped LXC container |
| `proxmox_container_stop` | Immediately stop an LXC container |
| `proxmox_container_shutdown` | Gracefully shut down an LXC container |
| `proxmox_container_reboot` | Reboot an LXC container |
| `proxmox_container_snapshot_list` | List snapshots for an LXC container |
| `proxmox_container_snapshot_create` | Create an LXC container snapshot |
| `proxmox_container_snapshot_rollback` | Rollback an LXC container to a snapshot |
| `proxmox_container_rrd` | Get RRD performance time-series data for an LXC container |

### Storage

| Tool | Description |
|------|-------------|
| `proxmox_list_storage` | List storage pools (cluster-wide or per node) |
| `proxmox_storage_content` | List disk images, ISOs, templates, and backups in a storage pool |
| `proxmox_storage_status` | Get capacity and usage statistics for a storage pool |

### Pools

| Tool | Description |
|------|-------------|
| `proxmox_list_pools` | List all resource pools in the cluster |
| `proxmox_pool_status` | Get members and details of a resource pool |

## Security

- **API token only** — password/ticket authentication is not supported.
- All path, node, VMID, and UPID parameters are validated with strict regex before use.
- Guest exec commands must be passed as a JSON array (e.g. `["ls", "-la", "/tmp"]`); no shell string is accepted, preventing shell injection.
- Guest file writes are capped at 1 MiB; path traversal (`..`) and null bytes are rejected.
- The container runs as a non-root user (`mcp`).
- TLS verification is off by default (common for self-signed Proxmox certs); set `VERIFY_SSL=1` in production environments with valid certificates.

## Development

```bash
# Lint, format, type-check
make lint
make fmt
make typecheck

# Build Docker image
make build

# Smoke test (requires HOST, PORT, API_TOKEN in env)
make smoke
```

Dependencies: `fastmcp==3.1.0`, `httpx==0.28.1`
