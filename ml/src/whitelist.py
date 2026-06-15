"""
whitelist.py  –  IP address whitelist loader.

Reads whitelist_ips.txt, which may contain:
  - IPv4 / IPv6 addresses (one per line)
  - Comment lines starting with '#'
  - Blank lines (ignored)
"""

import os


def allowed(ip):
    """Return True if *ip* is present in the IP whitelist file."""
    base_dir      = os.path.dirname(os.path.abspath(__file__))
    whitelist_path = os.path.join(base_dir, "../data/whitelist_ips.txt")

    try:
        with open(whitelist_path) as f:
            allowed_ips = set()
            for line in f:
                stripped = line.strip()
                # Skip blank lines and comment lines
                if not stripped or stripped.startswith("#"):
                    continue
                allowed_ips.add(stripped)
    except FileNotFoundError:
        # If the file is missing, treat every IP as unknown (not trusted)
        return False

    return ip in allowed_ips