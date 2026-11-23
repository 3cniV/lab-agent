import subprocess
import xml.etree.ElementTree as ET

from guardrails import check_target, EXCLUDED_HOSTS


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