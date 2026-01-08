# scanner.py
# Threaded TCP port scanner with best-effort banner grabbing and service hints.
# Exposes run_port_scan(host, start_port, end_port, threads, timeout)
# Returns a dict: { "timestamp": "YYYY-MM-DD HH:MM:SS", "results": [ {port, status, banner, service}, ... ] }

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import ssl
import datetime

# Friendly service names for common ports
COMMON_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP-Submission",
    636: "LDAPS",
    1433: "MSSQL",
    1521: "OracleDB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}

# Ports where an HTTP GET is likely to work
_HTTP_PORTS = {80, 8080, 8000, 5000, 3000}
_HTTPS_PORTS = {443, 8443}


def _recv_safe(sock, bufsize=2048):
    try:
        data = sock.recv(bufsize)
        return data or b""
    except Exception:
        return b""


def _try_http_probe(host, port, timeout):
    """Send a minimal HTTP GET (or HTTPS) and return response bytes (best-effort)."""
    req = f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: banner-grabber/1.0\r\n\r\n".encode("utf-8")
    try:
        if port in _HTTPS_PORTS:
            # SSL wrapped connection
            with socket.create_connection((host, port), timeout=timeout) as raw:
                raw.settimeout(timeout)
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                        ssock.settimeout(timeout)
                        ssock.sendall(req)
                        return _recv_safe(ssock, 4096)
                except Exception:
                    return b""
        else:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(req)
                return _recv_safe(s, 4096)
    except Exception:
        return b""


def _scan_one(host, port, timeout=1.0):
    """
    Try a TCP connect. If open, attempt to read an immediate banner,
    fallback to protocol-specific probes (HTTP/HTTPS), then a small harmless probe.
    Returns dict with port, status ("OPEN"/"CLOSED"/"ERROR"), banner, service.
    """
    service_hint = COMMON_SERVICES.get(port, "Unknown")
    banner = ""
    try:
        # Use create_connection for consistent behavior
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                # try to read any immediate banner (SSH/SMPP/SMTP often speak first)
                data = s.recv(1024)
                if data:
                    banner = data.decode("utf-8", errors="ignore").strip()
                else:
                    # If no immediate banner, try protocol probes for common ports
                    if port in _HTTP_PORTS or port in _HTTPS_PORTS:
                        data = _try_http_probe(host, port, timeout)
                        banner = data.decode("utf-8", errors="ignore").strip() if data else ""
                    else:
                        # harmless probe: send newline to elicit a response for some services
                        try:
                            s.sendall(b"\r\n")
                            data = s.recv(512)
                            banner = data.decode("utf-8", errors="ignore").strip() if data else ""
                        except Exception:
                            banner = ""
            except Exception:
                banner = ""
        return {
            "port": port,
            "status": "OPEN",
            "banner": (banner[:300] if banner else ""),
            "service": service_hint
        }
    except Exception:
        # connection failed/closed
        return {
            "port": port,
            "status": "CLOSED",
            "banner": "",
            "service": service_hint
        }


def run_port_scan(host="127.0.0.1", start_port=1, end_port=1024, threads=100, timeout=1.0):
    """
    Run a threaded scan over the given port range.
    Returns: { "timestamp": "YYYY-MM-DD HH:MM:SS", "results": [ {port, status, banner, service}, ... ] }
    """
    try:
        start = int(start_port)
        end = int(end_port)
        workers = max(1, int(threads))
        tout = float(timeout)
    except Exception as e:
        raise ValueError("Numeric params required") from e

    if start < 1 or end > 65535 or start > end:
        raise ValueError("Invalid port range")

    ports = range(start, end + 1)
    results = []

    # Bound max workers to a reasonable number
    max_workers = min(workers, 1000)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_scan_one, host, p, tout): p for p in ports}
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception:
                p = futures.get(fut, None)
                res = {
                    "port": p or -1,
                    "status": "ERROR",
                    "banner": "",
                    "service": COMMON_SERVICES.get(p, "Unknown")
                }
            results.append(res)

    results.sort(key=lambda x: x["port"])
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {"timestamp": timestamp, "results": results}


# Quick CLI test
if __name__ == "__main__":
    import argparse, json
    p = argparse.ArgumentParser(description="Scan ports and try to grab banners")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--start", type=int, default=1)
    p.add_argument("--end", type=int, default=1024)
    p.add_argument("--threads", type=int, default=100)
    p.add_argument("--timeout", type=float, default=1.0)
    args = p.parse_args()
    out = run_port_scan(args.host, args.start, args.end, args.threads, args.timeout)
    print(json.dumps(out, indent=2))
