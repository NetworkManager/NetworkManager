#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Red Hat, Inc.

from pathlib import Path
import subprocess
import itertools
import shutil
import sys
import os

xgettext = shutil.which("xgettext")

# Paths relative to repo root which should be
# excluded from pot->tree, or tree->pot checks.
ignore_in_potfiles = ()
ignore_in_tree = ()


def err(s):
    print(f"ERR: {s}", file=sys.stderr)


def read_potfile_list(root, path):
    with open(root / path, "r") as f:
        for line in f.readlines():
            stripped = line.strip()
            if stripped.startswith("#") or len(stripped) == 0:
                continue
            if stripped in ignore_in_potfiles:
                continue
            yield (root / stripped).resolve()


def get_existing_entries(root):
    in_list = read_potfile_list(root, "po/POTFILES.in")
    skip_list = read_potfile_list(root, "po/POTFILES.skip")
    return set(itertools.chain(in_list, skip_list))


def check_exists_in_tree(root, paths):
    is_ok = True

    for path in paths:
        if not path.exists():
            err(
                f"{path.relative_to(root)} exists in POTFILES.in or POTFILES.skip, but missing in sources"
            )
            is_ok = False

    return is_ok


def get_gettext_args(root):
    arg_name = "XGETTEXT_OPTIONS ="
    with open(root / "po" / "Makevars", "r") as f:
        for line in f.readlines():
            if line.startswith(arg_name):
                return line[len(arg_name) :].strip().split(" ")

    raise Exception("could not get gettext args")


def list_c_sources(root):
    for path, _, files in os.walk(root / "src"):
        for file in files:
            relpath_str = str(Path(path).relative_to(root) / file)
            extension = file.replace(".in", "").split(".").pop()
            if extension in ["c", "h"] and relpath_str not in ignore_in_tree:
                full_path = root / path / file
                yield full_path.resolve()


def gettext_dry_run(root, paths):
    args = get_gettext_args(root)
    process = subprocess.Popen(
        [xgettext, "--files-from=-", "--output=-"] + args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )

    for line in paths:
        process.stdin.write(f"{line.resolve()}\n")
    process.stdin.close()

    seen = set()
    for line in process.stdout:
        if line.startswith("#: "):
            out_path = Path(line.replace("#: ", "").split(":")[0])
            if out_path not in seen:
                seen.add(out_path)
                yield out_path

    process.stdout.close()
    assert process.wait() == 0


def check_exists_in_potfiles(root, pot_paths):
    unseen_paths = filter(lambda path: path not in pot_paths, list_c_sources(root))

    is_ok = True
    for path in gettext_dry_run(root, unseen_paths):
        err(
            f"{path.relative_to(root)} code contains gettext macros, but missing in POTFILES.in or POTFILES.skip"
        )
        is_ok = False

    return is_ok


def check_potfiles():
    root = (Path(os.path.dirname(__file__)) / "../../").resolve()
    file_entries = get_existing_entries(root)
    is_ok = True

    # Let's first check that all the files that we
    # have in POTFILES.* actually exist.
    is_ok &= check_exists_in_tree(root, file_entries)

    # Now the other direction -- check that all sources
    # that should be included in POTFILES, are included.
    is_ok &= check_exists_in_potfiles(root, file_entries)

    return is_ok


if __name__ == "__main__":
    if xgettext is None:
        raise Exception("xgettext is missing")

    out_msg = "POTFILES consistency check: %s"
    if check_potfiles():
        print(out_msg % "ok")
    else:
        print(out_msg % "failed", file=sys.stderr)
        sys.exit(1)
