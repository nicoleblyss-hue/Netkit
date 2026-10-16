#!/usr/bin/env python3
"""netkit - terminal network diagnostics for helpdesk work (stdlib only).

  python netkit.py                   # menu (Windows: pip install windows-curses)
  python netkit.py triage            # run one tool
  python netkit.py scan host 1-1024

Tools: triage local ping trace dns check cert http ip whois scan speed
Optional: pip install dnspython  (adds MX/NS/TXT/DMARC lookups to 'dns')
"""
import json, os, platform, re, shutil, socket, ssl, statistics, subprocess
import sys, threading, time, urllib.request, uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

WIN = platform.system() == "Windows"
UA = "netkit/2.0"
SERVICES = {"ssh": 22, "dns": 53, "http": 80, "ldap": 389, "https": 443, "smb": 445,
            "ldaps": 636, "sql": 1433, "rdp": 3389, "vnc": 5900, "printer": 9100}
COMMON = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 587, 993, 995,
          1433, 3306, 3389, 5432, 5900, 8080, 8443, 9100]


# ---------------------------------------------------------------- helpers
def sh(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def host_of(s):
    return re.sub(r"^\w+://", "", s.strip()).split("/")[0].split(":")[0]


def stream(cmd, stop):
    if not shutil.which(cmd[0]):
        yield f"'{cmd[0]}' not found on this system."
        return
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for line in p.stdout:
            if stop.is_set():
                break
            yield line.rstrip()
    finally:
        if p.poll() is None:
            p.terminate()


def tcp(host, port, timeout=2):
    """-> (open|closed|filtered|error, seconds)"""
    t = time.perf_counter()
    try:
        socket.create_connection((host, port), timeout).close()
        state = "open"
    except socket.timeout:
        state = "filtered"
    except ConnectionRefusedError:
        state = "closed"
    except OSError as e:
        state = f"error ({e})"
    return state, time.perf_counter() - t


def gateway():
    out = sh("route", "print", "0.0.0.0") if WIN else sh("ip", "route", "show", "default") or sh("route", "-n", "get", "default")
    m = re.search(r"(?:default via|gateway:|0\.0\.0\.0\s+0\.0\.0\.0)\s+([\d.]+)", out)
    return m and m.group(1)


def dns_servers():
    if WIN:
        return re.findall(r"DNS Servers[ .:]*([\d.]+)", sh("ipconfig", "/all"))
    try:
        return re.findall(r"^nameserver\s+(\S+)", open("/etc/resolv.conf").read(), re.M)
    except OSError:
        return []


def local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # no packet is sent
            return s.getsockname()[0]
    except OSError:
        return None


# ------------------------------------------------------------------ tools
# Each tool takes (arg, stop_event) and yields lines of text.
def t_triage(arg, stop):
    ip, gw = local_ip(), gateway()
    gw_ok = bool(gw) and "ttl" in sh("ping", "-n" if WIN else "-c", "1", gw).lower()
    net_ok = tcp("1.1.1.1", 443, 3)[0] == "open"
    try:
        socket.gethostbyname("example.com")
        dns_ok = True
    except OSError:
        dns_ok = False
    try:
        urllib.request.urlopen("https://example.com", timeout=6).close()
        web_ok = True
    except Exception:
        web_ok = False
    rows = [("IP address", bool(ip), ip or "none"),
            ("Gateway", gw_ok, gw or "not found"),
            ("Internet (1.1.1.1:443)", net_ok, ""),
            ("DNS (example.com)", dns_ok, ", ".join(dns_servers())),
            ("Web (https://example.com)", web_ok, "")]
    msgs = ["No IP address: check cable/Wi-Fi and DHCP.",
            "Gateway unreachable: check the link, switch/AP, or the router itself.",
            "Gateway OK but no internet: ISP or router uplink problem.",
            "Internet OK but DNS fails: check the DNS servers (try 1.1.1.1).",
            "DNS OK but web fails: proxy, firewall, or TLS/clock problem."]
    for label, ok, detail in rows:
        yield f"[{'OK' if ok else 'FAIL':<4}]  {label:<26} {detail}"
    fails = [m for (_, ok, _), m in zip(rows, msgs) if not ok]
    if not gw_ok and net_ok:
        fails = fails[1:]  # gateway may simply ignore ping
    yield ""
    yield fails[0] if fails else "All checks pass - problem is likely app/site-specific or intermittent."


def t_local(arg, stop):
    mac = ":".join(f"{(uuid.getnode() >> i) & 255:02x}" for i in range(40, -1, -8))
    yield f"Hostname  {socket.gethostname()}"
    yield f"OS        {platform.platform()}"
    yield f"IP        {local_ip() or 'none (no route)'}"
    yield f"Gateway   {gateway() or 'none'}"
    yield f"DNS       {', '.join(dns_servers()) or 'unknown'}"
    yield f"MAC       {mac}  (may be a virtual adapter)"
    if WIN:
        yield ""
        for line in sh("ipconfig", "/all").splitlines():
            if re.search(r"Description|Physical|IPv4|Subnet|Gateway|DHCP Server|DNS Servers", line):
                yield line.rstrip()


def t_ping(arg, stop):
    n, times = 20, []
    for line in stream(["ping", "-n" if WIN else "-c", str(n), host_of(arg)], stop):
        yield line
        if m := re.search(r"time[=<]\s*([\d.]+)", line):
            times.append(float(m.group(1)))
    if times:
        jitter = statistics.mean(abs(a - b) for a, b in zip(times, times[1:])) if len(times) > 1 else 0
        yield ""
        yield (f"Loss {100 * (n - len(times)) / n:.0f}%   min {min(times):.1f}   "
               f"avg {statistics.mean(times):.1f}   max {max(times):.1f}   jitter {jitter:.1f} ms")


def t_trace(arg, stop):
    h = host_of(arg)
    yield from stream(["tracert", "-d", h] if WIN else ["traceroute", "-n", h] if shutil.which("traceroute") else ["tracepath", "-n", h], stop)


def t_dns(arg, stop):
    name = host_of(arg)
    try:
        import dns.resolver
    except ImportError:
        yield "(dnspython not installed: addresses only. pip install dnspython for MX/NS/TXT)"
        try:
            yield from sorted({i[4][0] for i in socket.getaddrinfo(name, None)})
        except socket.gaierror as e:
            yield f"Lookup failed: {e}"
        return
    yield f"Resolver: {', '.join(dns.resolver.Resolver().nameservers)}"
    for label, q, rt in [(r, name, r) for r in ("A", "AAAA", "CNAME", "MX", "NS", "TXT")] + [("DMARC", "_dmarc." + name, "TXT")]:
        try:
            for r in dns.resolver.resolve(q, rt):
                yield f"{label:<6} {r.to_text()}"
        except Exception:
            yield f"{label:<6} -"


def t_check(arg, stop):
    parts = arg.split()
    if len(parts) != 2:
        yield f"Usage: <service|port> <host>   services: {', '.join(SERVICES)}"
        return
    svc, host = parts
    if svc.lower() not in SERVICES and not svc.isdigit() and (host.lower() in SERVICES or host.isdigit()):
        svc, host = host, svc  # allow "host service"
    port = SERVICES.get(svc.lower()) or (int(svc) if svc.isdigit() else None)
    if not port:
        yield f"Unknown service '{svc}'. Known: {', '.join(SERVICES)}"
        return
    state, dt = tcp(host, port, 3)
    yield f"{host}:{port} ({svc}) -> {state.upper()}  ({dt * 1000:.0f} ms)"
    yield {"open": "Reachable.",
           "closed": "Host is up but nothing is listening (service stopped?).",
           "filtered": "No reply: a firewall is dropping it, or the host is down."}.get(state, "")


def t_cert(arg, stop):
    host, _, p = arg.strip().replace("https://", "").split("/")[0].partition(":")
    try:
        with socket.create_connection((host, int(p or 443)), timeout=8) as s, \
                ssl.create_default_context().wrap_socket(s, server_hostname=host) as t:
            c = t.getpeercert()
    except ssl.SSLCertVerificationError as e:
        yield f"CERTIFICATE PROBLEM: {e.verify_message}"
        return
    except OSError as e:
        yield f"Connection failed: {e}"
        return
    left = (ssl.cert_time_to_seconds(c["notAfter"]) - time.time()) / 86400
    yield f"Subject   {dict(x[0] for x in c['subject']).get('commonName', '')}"
    yield f"Issuer    {dict(x[0] for x in c['issuer']).get('organizationName', '')}"
    yield f"Valid     {c['notBefore']}  ->  {c['notAfter']}"
    yield f"Expires   in {left:.0f} days{'  *** EXPIRING SOON ***' if left < 30 else ''}"
    yield "Names     " + ", ".join(v for _, v in c.get("subjectAltName", ()))
    yield "Chain is trusted and the hostname matches."


def t_http(arg, stop):
    u = urlparse(arg if "://" in arg else "https://" + arg)
    tls = u.scheme == "https"
    port = u.port or (443 if tls else 80)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    try:
        t0 = time.perf_counter()
        ai = socket.getaddrinfo(u.hostname, port, proto=socket.IPPROTO_TCP)[0]
        t1 = time.perf_counter()
        s = socket.create_connection(ai[4][:2], timeout=10)
        t2 = time.perf_counter()
        if tls:
            s = ssl.create_default_context().wrap_socket(s, server_hostname=u.hostname)
        t3 = time.perf_counter()
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {u.hostname}\r\nUser-Agent: {UA}\r\nConnection: close\r\n\r\n".encode())
        data = s.recv(4096)
        t4 = time.perf_counter()
        while chunk := s.recv(65536):
            data += chunk
        t5 = time.perf_counter()
        s.close()
    except Exception as e:
        yield f"Request failed: {e}"
        return
    head, _, body = data.partition(b"\r\n\r\n")
    h = head.decode(errors="replace").split("\r\n")
    yield f"{h[0]}   from {ai[4][0]}   ({len(body):,} bytes)"
    for label, a, b in [("DNS", t0, t1), ("TCP connect", t1, t2), ("TLS handshake", t2, t3),
                        ("Wait (TTFB)", t3, t4), ("Download", t4, t5), ("Total", t0, t5)]:
        yield f"  {label:<14}{(b - a) * 1000:8.1f} ms"
    yield ""
    yield from ("  " + line for line in h[1:])


def t_ip(arg, stop):
    fields = "status,message,query,country,regionName,city,timezone,isp,org,as,reverse,proxy,hosting,mobile"
    req = urllib.request.Request(f"http://ip-api.com/json/{host_of(arg)}?fields={fields}", headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            d = json.load(r)
    except Exception as e:
        yield f"Request failed: {e}"
        return
    if d.get("status") != "success":
        yield d.get("message", "Lookup failed")
        return
    for k in fields.split(",")[2:]:
        yield f"{k:<11} {d.get(k, '')}"


def whois_q(server, q):
    with socket.create_connection((server, 43), timeout=8) as s:
        s.sendall(f"{q}\r\n".encode())
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    return data.decode(errors="replace")


def rdap(q):
    kind = "ip" if re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+:[0-9a-fA-F:]*", q) else "domain"
    req = urllib.request.Request(f"https://rdap.org/{kind}/{q}",
                                 headers={"User-Agent": UA, "Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        d = json.load(r)
    yield f"Name        {d.get('ldhName') or d.get('name') or d.get('handle', '')}"
    yield f"Status      {', '.join(d.get('status', []))}"
    for k in ("startAddress", "endAddress", "country", "type"):
        if k in d:
            yield f"{k:<11} {d[k]}"
    for e in d.get("events", []):
        yield f"{e['eventAction']:<11} {e['eventDate']}"
    for ent in d.get("entities", []):
        if "registrar" in ent.get("roles", []):
            yield "Registrar   " + next((v[3] for v in ent.get("vcardArray", [0, []])[1] if v[0] == "fn"), "")
    for ns in d.get("nameservers", []):
        yield f"Nameserver  {ns.get('ldhName', '')}"


def t_whois(arg, stop):
    q = host_of(arg)
    try:
        text = whois_q("whois.iana.org", q)
        if m := re.search(r"^(?:refer|whois):\s*(\S+)", text, re.M):
            text = whois_q(m.group(1), q)
    except OSError as e:
        yield f"Port 43 whois failed ({e}); trying RDAP over HTTPS..."
        try:
            yield from rdap(q)
        except Exception as e2:
            yield f"RDAP failed too: {e2}"
        return
    yield from text.splitlines()


def ports_from(spec):
    if spec in ("", "common"):
        return COMMON
    out = set()
    for part in spec.split(","):
        a, _, b = part.partition("-")
        out.update(range(int(a), int(b or a) + 1))
    return sorted(p for p in out if 0 < p < 65536)


def t_scan(arg, stop):
    host, _, spec = arg.strip().partition(" ")
    try:
        ports, ip = ports_from(spec.strip()), socket.gethostbyname(host_of(host))
    except (ValueError, OSError) as e:
        yield f"Error: {e}"
        return
    yield f"Scanning {host} ({ip}), {len(ports)} ports. Only scan hosts you are authorized to test."
    t, found = time.perf_counter(), 0
    with ThreadPoolExecutor(200) as ex:
        futs = {ex.submit(tcp, ip, p, 0.6): p for p in ports}
        for f in as_completed(futs):
            if stop.is_set():
                for g in futs:
                    g.cancel()
                break
            if f.result()[0] == "open":
                found += 1
                try:
                    svc = socket.getservbyport(futs[f])
                except OSError:
                    svc = "?"
                yield f"  {futs[f]:>5}/tcp  {svc}"
    yield f"{found} open of {len(ports)} ports in {time.perf_counter() - t:.1f}s"


def t_speed(arg, stop):
    def get(path, data=None):
        req = urllib.request.Request("https://speed.cloudflare.com" + path, data=data, headers={"User-Agent": UA})
        return urllib.request.urlopen(req, timeout=20)
    try:
        lat = []
        for _ in range(5):
            t = time.perf_counter()
            get("/__down?bytes=0").read()
            lat.append((time.perf_counter() - t) * 1000)
        yield f"Latency   min {min(lat):.0f} ms   avg {statistics.mean(lat):.0f} ms"
        yield "Downloading 25 MB ..."
        t = time.perf_counter()
        n = len(get("/__down?bytes=25000000").read())
        yield f"Download  {n * 8 / (time.perf_counter() - t) / 1e6:.1f} Mbps"
        yield "Uploading 10 MB ..."
        t = time.perf_counter()
        get("/__up", b"\0" * 10_000_000).read()
        yield f"Upload    {80 / (time.perf_counter() - t):.1f} Mbps"
    except Exception as e:
        yield f"Speed test failed: {e}"


# menu name, cli name, function, prompt (None = no input), default input
TOOLS = [
    ("Triage (is it down?)", "triage", t_triage, None, ""),
    ("Local network info", "local", t_local, None, ""),
    ("Ping + loss/jitter", "ping", t_ping, "Host", "1.1.1.1"),
    ("Traceroute", "trace", t_trace, "Host", "example.com"),
    ("DNS records", "dns", t_dns, "Domain", "example.com"),
    ("Service check", "check", t_check, "Service and host, e.g. rdp pc-name", "rdp localhost"),
    ("TLS certificate", "cert", t_cert, "Host[:port]", "example.com"),
    ("HTTP timing", "http", t_http, "URL", "https://example.com"),
    ("IP intel", "ip", t_ip, "IP or host (blank = your IP)", ""),
    ("Whois", "whois", t_whois, "Domain or IP", "example.com"),
    ("Port scan", "scan", t_scan, "Host [ports], e.g. host 1-1024", "localhost"),
    ("Speed test", "speed", t_speed, None, ""),
]


# -------------------------------------------------------- save / copy output
def save(name, lines):
    fn = f"netkit-{name.split()[0].lower()}-{datetime.now():%Y%m%d-%H%M%S}.txt"
    with open(fn, "w") as f:
        f.write("\n".join(lines) + "\n")
    return f"Saved to {fn}"


def copy(text):
    for c in (["clip"], ["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"]):
        if shutil.which(c[0]):
            subprocess.run(c, input=text, text=True)
            return "Copied to clipboard"
    return "No clipboard tool found (press s to save instead)"


# ------------------------------------------------------------------- TUI
def tui():
    os.environ.setdefault("ESCDELAY", "25")
    try:
        import curses
    except ImportError:
        sys.exit("curses not available. On Windows: pip install windows-curses")

    def put(w, y, x, s, a=0):
        h, wd = w.getmaxyx()
        if 0 <= y < h and x < wd - 1:
            try:
                w.addnstr(y, x, s, wd - x - 1, a)
            except curses.error:
                pass

    def ask(scr, label, default):
        buf = ""
        curses.curs_set(1)
        while True:
            scr.erase()
            put(scr, 1, 2, label, curses.A_BOLD)
            put(scr, 2, 2, f"Enter = run, Esc = cancel (default: {default or 'none'})", curses.A_DIM)
            put(scr, 4, 2, "> " + buf)
            ch = scr.getch()
            if ch in (10, 13, curses.KEY_ENTER):
                curses.curs_set(0)
                return buf.strip() or default
            if ch == 27:
                curses.curs_set(0)
                return None
            if ch in (8, 127, curses.KEY_BACKSPACE):
                buf = buf[:-1]
            elif 32 <= ch < 127:
                buf += chr(ch)

    def view(scr, name, func, arg):
        lines, done, stop = [], threading.Event(), threading.Event()

        def work():
            try:
                for line in func(arg, stop):
                    lines.append(line)
            except Exception as e:
                lines.append(f"Error: {e}")
            done.set()

        threading.Thread(target=work, daemon=True).start()
        top, follow, note = 0, True, ""
        scr.timeout(100)
        while True:
            h, _ = scr.getmaxyx()
            body = h - 2
            mx = max(0, len(lines) - body)
            top = mx if follow else min(top, mx)
            scr.erase()
            put(scr, 0, 0, f" {name}: {arg} [{'done' if done.is_set() else 'running'}] ", curses.A_REVERSE)
            for i, line in enumerate(lines[top:top + body]):
                put(scr, 1 + i, 1, line)
            put(scr, h - 1, 1, note or "q back | arrows/PgUp/PgDn scroll | s save | c copy", curses.A_DIM)
            ch = scr.getch()
            if ch in (ord("q"), 27):
                stop.set()
                scr.timeout(-1)
                return
            if ch in (curses.KEY_UP, ord("k")):
                top, follow = max(0, top - 1), False
            elif ch in (curses.KEY_DOWN, ord("j")):
                top = min(mx, top + 1)
                follow = top == mx
            elif ch == curses.KEY_PPAGE:
                top, follow = max(0, top - body), False
            elif ch == curses.KEY_NPAGE:
                top = min(mx, top + body)
                follow = top == mx
            elif ch == ord("s"):
                note = save(name, lines)
            elif ch == ord("c"):
                note = copy("\n".join(lines))

    def menu(scr):
        curses.curs_set(0)
        sel = 0
        while True:
            h, _ = scr.getmaxyx()
            scr.erase()
            put(scr, 0, 1, " NETKIT ", curses.A_REVERSE)
            for i, t in enumerate(TOOLS):
                put(scr, 2 + i, 2, f" {t[0]:<26}", curses.A_REVERSE if i == sel else 0)
            put(scr, h - 1, 1, "Up/Down move | Enter select | q quit", curses.A_DIM)
            ch = scr.getch()
            if ch in (ord("q"), 27):
                return
            if ch in (curses.KEY_UP, ord("k")):
                sel = (sel - 1) % len(TOOLS)
            elif ch in (curses.KEY_DOWN, ord("j")):
                sel = (sel + 1) % len(TOOLS)
            elif ch in (10, 13, curses.KEY_ENTER):
                name, _, fn, label, default = TOOLS[sel]
                arg = "" if label is None else ask(scr, f"{name}: {label}", default)
                if arg is not None:
                    view(scr, name, fn, arg)

    curses.wrapper(menu)


# ------------------------------------------------------------------- CLI
def cli(argv):
    by = {t[1]: t for t in TOOLS}
    if argv[0] not in by:
        print(__doc__)
        return
    fn, default = by[argv[0]][2], by[argv[0]][4]
    stop = threading.Event()
    try:
        for line in fn(" ".join(argv[1:]) or default, stop):
            print(line, flush=True)
    except KeyboardInterrupt:
        stop.set()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli(sys.argv[1:])
    else:
        tui()
