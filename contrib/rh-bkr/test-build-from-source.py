#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name("build-from-source.sh")
FDO = "https://gitlab.freedesktop.org/NetworkManager/NetworkManager.git"
GITHUB = "https://github.com/NetworkManager/NetworkManager.git"


class TestBuildFromSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real_git = shutil.which("git")
        if cls.real_git is None:
            raise unittest.SkipTest("git is required")
        cls.temporary = tempfile.TemporaryDirectory(prefix="nm-source-test-")
        cls.root = Path(cls.temporary.name)
        config = cls.root / "gitconfig"
        config.touch()
        bin_dir = cls.root / "bin"
        bin_dir.mkdir()
        rpmkeys = bin_dir / "rpmkeys"
        rpmkeys.write_text("#!/bin/sh\nexit 0\n")
        rpmkeys.chmod(0o755)
        git_spy = bin_dir / "git"
        git_spy.write_text(
            "#!{}\n".format(sys.executable)
            + "import json, os, sys\n"
            + "with open(os.environ['NM_TEST_GIT_LOG'], 'a') as stream:\n"
            + "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            + "os.execv({0!r}, [{0!r}] + sys.argv[1:])\n".format(cls.real_git)
        )
        git_spy.chmod(0o755)
        cls.env = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith(("GIT_", "BASH_FUNC_"))
            and name not in ("BASH_ENV", "ENV")
        }
        cls.env.update(
            GIT_CONFIG_GLOBAL=str(config),
            GIT_CONFIG_NOSYSTEM="1",
            GIT_ALLOW_PROTOCOL="file",
            GIT_TERMINAL_PROMPT="0",
            PATH="{}:{}".format(bin_dir, os.environ.get("PATH", os.defpath)),
        )
        fixtures = {}
        for name in ("fdo", "github", "retained sources.git"):
            repo = cls.root / name
            cls.git("init", repo)
            cls.git("-C", repo, "checkout", "-b", "main")
            cls.git("-C", repo, "commit", "--allow-empty", "-m", name)
            cls.git("-C", repo, "tag", "-a", "1.58.0", "-m", "fixture")
            fixtures[name] = (repo, cls.git("-C", repo, "rev-parse", "HEAD"))

        cls.fdo, cls.fdo_head = fixtures["fdo"]
        cls.github, cls.github_head = fixtures["github"]
        cls.internal, cls.internal_base = fixtures["retained sources.git"]
        cls.git("-C", cls.fdo, "update-ref", "refs/merge-requests/7/head", cls.fdo_head)
        cls.git("-C", cls.github, "update-ref", "refs/pull/9/head", cls.github_head)
        cls.git("-C", cls.internal, "checkout", "-b", "emergency")
        cls.git("-C", cls.internal, "commit", "--allow-empty", "-m", "internal fix")
        cls.internal_head = cls.git("-C", cls.internal, "rev-parse", "HEAD")
        cls.git("config", "--file", config, "url.{}.insteadOf".format(cls.fdo), FDO)
        cls.git(
            "config", "--file", config, "url.{}.insteadOf".format(cls.github), GITHUB
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def git(cls, *args):
        return subprocess.run(
            [
                cls.real_git,
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
            ]
            + [str(arg) for arg in args],
            env=cls.env,
            check=True,
            universal_newlines=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.strip()

    def run_case(self, source, revision, expected_head):
        origin = source or FDO
        remotes = ["origin"] if source else ["github", "origin"]
        case_root = self.root / self._testMethodName
        case_root.mkdir()
        log = case_root / "git.jsonl"
        case_env = dict(self.env)
        case_env.update(
            BUILD_DIR=str(case_root / "build"),
            BUILD_ID=revision,
            NM_TEST_GIT_LOG=str(log),
            ARCH="x86_64",
            INSTALL_DEPENDENCIES="no",
            DO_TEST_BUILD="no",
            DO_TEST_PACKAGE="no",
            DO_INSTALL="no",
            SUDO="",
        )
        case_env.pop("BUILD_REPO", None)
        if source is not None:
            case_env["BUILD_REPO"] = str(source)
        result = subprocess.run(
            ["bash", str(SCRIPT)],
            env=case_env,
            universal_newlines=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        repo = Path(case_env["BUILD_DIR"]) / "NetworkManager"
        self.assertEqual(
            result.returncode == 0,
            expected_head is not None,
            result.stdout + result.stderr,
        )
        self.assertEqual(self.git("-C", repo, "remote").splitlines(), remotes)
        self.assertEqual(
            self.git("-C", repo, "config", "remote.origin.url"), str(origin)
        )
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        fetches = [call for call in calls if call[0] == "fetch"]
        if source:
            self.assertEqual(fetches, [["fetch", "origin", "--prune"]])
        else:
            self.assertEqual(
                fetches, [["fetch", "github"], ["fetch", "--all", "--prune"]]
            )
            self.assertEqual(
                self.git("-C", repo, "config", "remote.github.url"), GITHUB
            )
            self.assertEqual(
                self.git("-C", repo, "rev-parse", "refs/remotes/github/pr/9"),
                self.github_head,
            )
            self.assertEqual(
                self.git("-C", repo, "rev-parse", "refs/remotes/origin/pr/7"),
                self.fdo_head,
            )
        if expected_head is not None:
            self.assertEqual(self.git("-C", repo, "rev-parse", "HEAD"), expected_head)
            source_repo = {FDO: self.fdo, GITHUB: self.github}.get(str(origin), origin)
            for ref in ("refs/tags/1.58.0", "refs/nmbuild-origin/tags/1.58.0"):
                self.assertEqual(
                    self.git("-C", repo, "rev-parse", ref),
                    self.git("-C", source_repo, "rev-parse", "refs/tags/1.58.0"),
                )
            self.assertEqual(
                self.git("-C", repo, "rev-parse", "refs/nmbuild-origin/heads/main"),
                self.git("-C", source_repo, "rev-parse", "main"),
            )

    def test_unset(self):
        self.run_case(None, "main", self.fdo_head)

    def test_empty(self):
        self.run_case("", "origin/pr/7", self.fdo_head)

    def test_internal_branch(self):
        self.run_case(self.internal, "emergency", self.internal_head)

    def test_internal_tag(self):
        self.run_case(self.internal, "1.58.0", self.internal_base)

    def test_internal_commit(self):
        self.run_case(self.internal, self.internal_head, self.internal_head)

    def test_explicit_fdo(self):
        self.run_case(FDO, "origin/pr/7", self.fdo_head)

    def test_explicit_github(self):
        self.run_case(GITHUB, "origin/pr/9", self.github_head)

    def test_missing_repo(self):
        absent = self.root / "absent"
        self.run_case(absent, "main", None)

    def test_missing_ref(self):
        self.run_case(self.internal, "absent-ref", None)


if __name__ == "__main__":
    unittest.main()
