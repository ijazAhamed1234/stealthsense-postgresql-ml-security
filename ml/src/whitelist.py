import os

def allowed(ip):

    base_dir = os.path.dirname(os.path.abspath(__file__))

    whitelist_path = os.path.join(base_dir, "../data/whitelist_ips.txt")

    with open(
    whitelist_path
    ) as f:

        ips=[

        x.strip()

        for x in f

        ]

    return ip in ips