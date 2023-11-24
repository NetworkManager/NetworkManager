#!/usr/bin/env python3

from textwrap import wrap
import subprocess
import ipaddress
import argparse
import os
import re


domains = []

hosts_sub = {}
host_next = 0

macs_sub = {}
mac_next = 0

ips_sub = {}
ip4_next = ipaddress.IPv4Address("0.0.0.0")
ip6_next = ipaddress.IPv6Address("ffff::")


def main(args):
    must_autoreplace_hostnames = not args.show_hostnames
    must_replace_hostnames = must_autoreplace_hostnames or args.domain or args.hostname

    init_hostnames_and_domains_sub(args)

    with open(args.log_file) as f:
        for line in (line.strip() for line in f):
            if must_replace_hostnames:
                line = replace_hostnames(line, must_autoreplace_hostnames)
            if not args.show_macs:
                line = replace_macs(line)
            if not args.show_public_ips or args.hide_private_ips:
                line = replace_ips(line, args.show_public_ips, args.hide_private_ips)

            print(line)


def init_hostnames_and_domains_sub(args):
    global domains

    if not args.show_hostnames:
        domains.extend(["com", "org", "net", "gov", "es", "it"])

        r = subprocess.run("hostname", capture_output=True)
        if r.returncode == 0:
            own_hostname = r.stdout.decode().strip()
            add_host_sub(own_hostname, ".self")

    # domains and hostname passed explicitly are replaced even with --show-hostnames
    domains.extend(d.strip(". ") for d in args.domain)
    domains = "|".join(domains)

    for hostname in args.hostname:
        add_host_sub(hostname)


def add_host_sub(hostname: str, suffix: str = ""):
    global hosts_sub
    global host_next

    # if it's a domain-like hostname (i.e example.com) adds .ext at the end
    if suffix == "" and re.search(r"\.({})$".format(domains), hostname):
        suffix = ".ext"

    if hostname not in hosts_sub:
        hosts_sub[hostname] = "hostname{}{}".format(host_next, suffix)
        host_next += 1


def replace_hostnames(line: str, autodetect_from_logs: bool) -> str:
    global hosts_sub

    # look for known log messages that show hostnames
    if autodetect_from_logs:
        match = re.search(r"get-hostname: \"(.*)\"", line)
        if match:
            add_host_sub(match.group(1))

        match = re.search(r"set hostname to \"(.*)\"", line)
        if match:
            add_host_sub(match.group(1))

        match = re.search(
            r"hostname changed from (\(none\)|\".*\") to (\(none\)|\".*\")", line
        )
        if match:
            if match.group(1) != "(none)":
                add_host_sub(match.group(1).strip('"'))
            if match.group(2) != "(none)":
                add_host_sub(match.group(2).strip('"'))

    # look for domain-like strings
    if domains:
        match = re.search(r"[\w\-\.]+?\.(" + domains + r")\b", line)
        if match:
            add_host_sub(match.group(0))

    for orig, repl in hosts_sub.items():
        line = line.replace(orig, repl)

    return line


def replace_macs(line: str) -> str:
    global macs_sub
    global mac_next

    macs = re.findall(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", line)

    for mac in macs:
        if mac not in macs_sub:
            macs_sub[mac] = ":".join(wrap("{:012x}".format(mac_next), width=2))
            mac_next += 1

        line = line.replace(mac, macs_sub[mac])

    return line


def replace_ips(line: str, show_public: bool, hide_private: bool) -> str:
    global ips_sub
    global ip4_next
    global ip6_next

    ips4 = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", line)
    ips6 = re.findall(r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}", line)

    for addr_str in ips4 + ips6:
        try:
            addr = ipaddress.ip_address(addr_str)
        except:  # not IP
            continue

        if (addr.is_private and not hide_private) or (addr.is_global and show_public):
            continue

        if addr.exploded not in ips_sub:
            if type(addr) is ipaddress.IPv4Address:
                ips_sub[addr.exploded] = str(ip4_next).replace("0.", "IP4.", 1)
                ip4_next += 1
            else:
                ips_sub[addr.exploded] = str(ip6_next).replace("ffff:", "IPv6:", 1)
                ip6_next += 1

        line = line.replace(addr_str, ips_sub[addr.exploded])

    return line


if __name__ == "__main__":
    args_parser = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        description="""Anonymize some data from NetworkManager logs.

Note that it only covers some common stuff like MAC and IP addresses or
hostnames.  Do not trust it and manually review that the log doesn't contain
sensitive data before sharing it.

Changing IP address can make that problems related to routing are impossible to
analyze. Because of that, private IPs which are normally not sensitive are not
hidden by default, and if the problem is related to routing you might need to
use the --show-public-ips option""",
        epilog="Options of the type --show-* disable masking that type of data.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    args_parser.add_argument("-H", "--show-hostnames", action="store_true")
    args_parser.add_argument("-m", "--show-macs", action="store_true")
    args_parser.add_argument("-g", "--show-public-ips", action="store_true")
    args_parser.add_argument("-p", "--hide-private-ips", action="store_true")
    args_parser.add_argument(
        "-d",
        "--domain",
        action="append",
        default=[],
        help='additional domains to hide, like ".xyz", can be passed more than once',
    )
    args_parser.add_argument(
        "-n",
        "--hostname",
        action="append",
        default=[],
        help="additional hostnames to hide, can be passed more than once",
    )
    args_parser.add_argument(
        "log_file", nargs="?", default="/dev/stdin", help="Log file (by default, stdin)"
    )

    args = args_parser.parse_args()
    main(args)
