#!/usr/bin/env python3

import datetime
import os
import sys

try:
    import yaml
except ImportError:
    print("Error: missing pyyaml. Install with `pip install pyyaml`.", file=sys.stderr)
    quit(code=1)


# These are the distros that we currently check, ordered by priority to be chosen as Tier 1
ci_distros = ("fedora", "centos", "debian", "ubuntu", "alpine")


def _parse_date(date_str) -> datetime.date:
    return datetime.datetime.strptime(date_str, "%Y-%m-%d").date()


def _is_supported(val_str, today) -> bool:
    val_str = val_str.lower()
    if val_str in ("yes", "true"):
        return True
    elif val_str in ("no", "false"):
        return False
    else:
        support_date = _parse_date(val_str)
        return today <= support_date


def _nm_version_is_newer(nm_ver, nm_ver_from):
    if nm_ver == "main":
        return nm_ver_from != "main"  # main is newer than anything except main itself
    elif nm_ver_from == "main":
        return False
    nm_ver = nm_ver.split(".")
    nm_ver_from = nm_ver_from.split(".")
    if int(nm_ver[0]) > int(nm_ver_from[0]):
        return True
    elif nm_ver[0] == nm_ver_from[0] and int(nm_ver[1]) > int(nm_ver_from[1]):
        return True
    return False


def _print_usage():
    print("Usage: distros_support.py [-a|--all] | <nm_version>")
    print(" -a|--all:   print NM versions still active in any distro")
    print(" nm_version: print all info and config.yml file of the specified NM version")


if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help", "help"):
    _print_usage()
    quit()
elif len(sys.argv) > 2:
    print("Error: wrong arguments.", file=sys.stderr)
    _print_usage()
    quit(code=1)

today = datetime.date.today()
with open(os.path.dirname(__file__) + "/distros-info.yml") as f:
    distros_info = yaml.load(f, Loader=yaml.BaseLoader)

# Warn about EOL'd distros to remove them
for distro, versions in distros_info.items():
    for info in versions:
        if _is_supported(info["support"], today):
            continue
        if "extended-support" in info and _is_supported(
            info["extended-support"], today
        ):
            continue
        print(
            f"Warn: {distro} {info['version']} reached EOL, consider deleting this entry",
            file=sys.stderr,
        )

# If --all is selected, print all active NM versions and return
if len(sys.argv) < 2 or sys.argv[1] in ("-a", "--all"):
    nm_versions = {}

    for distro, versions in distros_info.items():
        for info in versions:
            if not _is_supported(info["support"], today):
                continue
            nm_versions.setdefault(info["nm"], []).append(f"{distro} {info['version']}")

    for nm_ver, distros in sorted(nm_versions.items(), reverse=True):
        print("- NM {}: {}".format(nm_ver, ", ".join(distros)))

    quit()

# Otherwise, print all the info related to the specified NM version
nm_version = sys.argv[1]

# Print distros that uses this nm_version
print(f"# List of distros using NM {nm_version}")
print("---")
for distro, versions in distros_info.items():
    for info in versions:
        if nm_version == info["nm"] and _is_supported(info["support"], today):
            try:
                support_end_date = _parse_date(info["support"])
                print(
                    f"- {distro} {info['version']}, supported until {info['support']}"
                )
            except ValueError:
                print(f"- {distro} {info['version']}, supported")

# Collect info about what distros should be Tier 2 and 3
tier2 = {}
tier3 = {}
for distro, versions in distros_info.items():
    if distro not in ci_distros:
        continue
    for info in versions:
        if not _is_supported(info["support"], today):
            continue
        if nm_version == info["nm"]:
            tier2.setdefault(distro, []).append(info["version"])
        elif _nm_version_is_newer(nm_version, info["nm"]):
            tier3.setdefault(distro, []).append(info["version"])

# Select a Tier1 distro
tier1_distro, tier1_version = "", ""

for fed_ver_info in distros_info["fedora"]:
    # We prefer the Fedora version marked as tier1-default
    if fed_ver_info.get("tier1-default", False):
        for tier in (tier2, tier3):
            if fed_ver_info["version"] in tier.get("fedora", []):
                tier1_distro = "fedora"
                tier1_version = fed_ver_info["version"]
                tier["fedora"].remove(fed_ver_info["version"])
                if not tier["fedora"]:
                    del tier["fedora"]

for distro in ci_distros:
    if tier1_distro:
        break

    for tier in (tier2, tier3):
        if distro in tier:
            # Exception: we want to use fedora:latest instead of fedora:rawhide because
            # we don't want lot of build failures in Tier 1, which is run for every MR.
            # We just ignore fedora:rawhide for Tier 1.
            if distro == "fedora" and tier[distro][0] == "rawhide":
                if len(tier[distro]) == 1:
                    continue
                idx = 1
            else:
                idx = 0

            tier1_distro = distro
            tier1_version = tier[distro].pop(idx)
            if not tier[distro]:
                del tier[distro]
            break

if not tier1_distro or not tier1_version:
    print("Warn: no suitable distro for Tier 1 found", file=sys.stderr)

# Always add CentOS Stream at least as Tier 3
for centos_ver_info in distros_info["centos"]:
    version = centos_ver_info["version"]
    found = False

    if tier1_distro == "centos" and tier1_version == version:
        found = True
    for tier in (tier2, tier3):
        if "centos" in tier and version in tier["centos"]:
            found = True
            break

    if not found:
        tier3.setdefault("centos", []).append(version)

# Print the config.yml needed for the corresponding stable branch
branch = "main" if nm_version == "main" else "nm-" + nm_version.replace(".", "-")
print("\n# .gitlab-ci/config.yml for branch '{}'".format(branch))
print(
    """---
# This file contains the configuration for the gitlab ci.
#
# To recreate the .gitlab-ci.yml file, run
#   ci-fairy generate-template
#
# The ci-fairy tool is part of
# https://gitlab.freedesktop.org/freedesktop/ci-templates
#

# Some distros are fairly similar, and we reuse similar scripts.
# The base type maps the distro name to their base.
base_types:
  fedora: fedora
  centos: fedora
  debian: debian
  ubuntu: debian
  alpine: alpine

# The list of all distributions we want to create job for.
distributions:
  # TIER 1: CI run for all MRs.
  # The first tier:1 in the list is used to build the pages and check-{tree,patch}."""
)
print("  - name: {}".format(tier1_distro))
print("    tier: 1")
print("    versions:")
print("      - '{}'".format(tier1_version))

print(
    """
  # TIER 2: distribution versions that will or might use the current NM version.
  # Run when doing a release."""
)
for distro, versions in tier2.items():
    print("  - name: {}".format(distro))
    print("    tier: 2")
    print("    versions:")
    for version in versions:
        print("      - '{}'".format(version))

print(
    """
  # TIER 3: distribution versions not in EOL but don't use the current NM version.
  # Run when doing a release, but a failure won't be blocking for the release."""
)
for distro, versions in tier3.items():
    print("  - name: {}".format(distro))
    print("    tier: 3")
    print("    versions:")
    for version in versions:
        print("      - '{}'".format(version))
