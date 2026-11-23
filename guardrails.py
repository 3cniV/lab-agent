import ipaddress

# Only these networks may ever be scanned. Edit to match your lab.
ALLOWED_NETWORKS = [ipaddress.ip_network("192.168.56.0/24")]

# Never scan these: your laptop (host) and the Kali VM itself.
EXCLUDED_HOSTS = ["192.168.56.1", "192.168.56.108"]


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