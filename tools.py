import os
import subprocess
import xml.etree.ElementTree as ET

from guardrails import check_target, EXCLUDED_HOSTS

# Named port profiles. The model can only pick from this menu, never pass raw Nmap flags.
SCAN_PROFILES = {
    "top100": ["--top-ports", "100"],
    "top1000": ["--top-ports", "1000"],
    "extended": ["-p", "1-10000"],
    "full": ["-p-"],
}


def scan_hosts(subnet: str) -> dict:
    """Host discovery (ping scan) on an allowlisted subnet."""
    check_target(subnet)
    cmd = ["nmap", "-sn", "-oX", "-", "--exclude", ",".join(EXCLUDED_HOSTS), subnet]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        return {"error": proc.stderr.strip()}

    root = ET.fromstring(proc.stdout)
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = None
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac = a.get("addr")
        name = h.find("hostnames/hostname")
        hosts.append({
            "ip": ip,
            "hostname": name.get("name") if name is not None else None,
            "mac": mac,
        })
    return {"subnet": subnet, "count": len(hosts), "hosts_up": hosts}


def scan_services(host: str, profile: str = "_PROFILE_DESC") -> dict:
    """Service/version detection on ONE allowlisted host, using a named port profile."""
    check_target(host)
    if "/" in host:
        return {"error": "scan_services takes a single host, not a network"}
    if host in EXCLUDED_HOSTS:
        return {"error": f"{host} is excluded from scanning"}
    if profile not in SCAN_PROFILES:
        return {"error": f"unknown profile {profile!r}; choose from {list(SCAN_PROFILES)}"}

    cmd = ["nmap", "-sV", *SCAN_PROFILES[profile], "-T4", "-oX", "-", host]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        return {"error": proc.stderr.strip()}

    root = ET.fromstring(proc.stdout)
    ports = []
    for p in root.findall("host/ports/port"):
        state = p.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = p.find("service")
        ports.append({
            "port": int(p.get("portid")),
            "protocol": p.get("protocol"),
            "service": svc.get("name") if svc is not None else None,
            "product": svc.get("product") if svc is not None else None,
            "version": svc.get("version") if svc is not None else None,
        })
    return {"host": host, "profile": profile, "open_ports": ports}

_DESC_DESCRIPTIVE = "PASTE YOUR CURRENT profile description text here (the 'fast, shallow ... slow' wording)"
_DESC_NEUTRAL = ("Scan profile. top100 = the 100 most common TCP ports. "
                 "top1000 = the 1000 most common TCP ports. "
                 "extended = TCP ports 1-10000. full = all 65535 TCP ports.")
_PROFILE_DESC = _DESC_NEUTRAL if os.environ.get("TOOL_DESC") == "neutral" else _DESC_DESCRIPTIVE

TOOL_SCHEMAS = [
    {
        "name": "scan_hosts",
        "description": "Ping-scan an allowlisted lab subnet and list live hosts (IP, hostname, MAC).",
        "input_schema": {
            "type": "object",
            "properties": {
                "subnet": {"type": "string", "description": "CIDR, e.g. 172.17.0.0/24"},
            },
            "required": ["subnet"],
        },
    },
    {
        "name": "scan_services",
        "description": (
            "Detect open ports and service versions on ONE allowlisted host. "
            "profile sets how many TCP ports are probed: top100 (fast, shallow), "
            "top1000, extended (ports 1-10000), full (all 65535, slow)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Single IPv4 address"},
                "profile": {"type": "string", "enum": ["top100", "top1000", "extended", "full"]},
            },
            "required": ["host"],
        },
    },
]

REGISTRY = {"scan_hosts": scan_hosts, "scan_services": scan_services}


def run_tool(name: str, args: dict) -> dict:
    """Run a tool by name. Errors are returned to the model, not raised."""
    fn = REGISTRY.get(name)
    if fn is None:
        return {"error": f"unknown tool: {name}"}
    try:
        return fn(**args)
    except (ValueError, PermissionError) as e:
        return {"error": str(e)}              # guardrail refusals
    except TypeError as e:
        return {"error": f"bad arguments: {e}"}
    except subprocess.TimeoutExpired:
        return {"error": "scan timed out"}
    except ET.ParseError:
        return {"error": "could not parse nmap output"}