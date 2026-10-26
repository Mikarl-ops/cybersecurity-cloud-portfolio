"""Validate an IP feed and write a reviewable iptables script. No rules are applied."""

import argparse
import ipaddress
from pathlib import Path


def read_ip_feed(ip_list_file):
    """Return unique canonical IP addresses, rejecting the whole feed on bad input."""
    addresses = []
    seen = set()
    with open(ip_list_file, "r", encoding="utf-8") as source:
        for line_number, raw_line in enumerate(source, start=1):
            candidate = raw_line.split("#", 1)[0].strip()
            if not candidate:
                continue
            try:
                address = str(ipaddress.ip_address(candidate))
            except ValueError as exc:
                raise ValueError(f"Invalid IP address on line {line_number}: {candidate!r}") from exc
            if address not in seen:
                addresses.append(address)
                seen.add(address)
    return addresses


def generate_firewall_rules(ip_list_file, output_script):
    """Validate all input first, then write IPv4/IPv6 commands without executing them."""
    addresses = read_ip_feed(ip_list_file)
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "# Review these rules before applying them to a host.",
        "",
    ]
    for address in addresses:
        command = "iptables" if ipaddress.ip_address(address).version == 4 else "ip6tables"
        lines.append(
            f"{command} -C INPUT -s {address} -j DROP 2>/dev/null "
            f"|| {command} -A INPUT -s {address} -j DROP"
        )
    lines.append("")
    Path(output_script).write_text("\n".join(lines), encoding="utf-8")
    return addresses


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ip_feed", help="Text file containing one IPv4 or IPv6 address per line")
    parser.add_argument("output_script", help="Path for the generated shell script")
    args = parser.parse_args()
    addresses = generate_firewall_rules(args.ip_feed, args.output_script)
    print(f"Wrote {len(addresses)} validated rules to {args.output_script}")


if __name__ == "__main__":
    main()
