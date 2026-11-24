import ipaddress

# Only these networks may ever be scanned.
ALLOWED_NETWORKS = [
    ipaddress.ip_network("192.168.56.0/24"),   # VirtualBox host-only lab network
    ipaddress.ip_network("172.17.0.0/24"),     # Docker bridge (Metasploitable container)
]

# Never scan: laptop, VirtualBox DHCP server, Kali itself (both addresses).
EXCLUDED_HOSTS = ["192.168.56.1", "192.168.56.100", "192.168.56.108", "172.17.0.1"]


def check_target(target: str) -> None:
    """Raise if the target isn't a valid address/network inside the allowlist."""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise ValueError(f"Invalid target: {target!r}")
    allowed = any(
        net.version == a.version and net.subnet_of(a) for a in ALLOWED_NETWORKS
    )
    if not allowed:
        raise PermissionError(f"Target {target} is outside the lab allowlist")