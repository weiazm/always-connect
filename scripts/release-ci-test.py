#!/usr/bin/env python3
"""Failure injection for the release gate and draft-to-public boundary. No network."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("release_ci", Path(__file__).with_name("release-ci.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
SHA = "a" * 40


def ci(**changes):
    return dict({"id": 1, "head_sha": SHA, "event": "push", "head_branch": "main",
                 "status": "completed", "conclusion": "success"}, **changes)


class GateTests(unittest.TestCase):
    def test_real_gate_rejects_version_checkout_and_main_mismatches(self):
        with tempfile.TemporaryDirectory() as scratch:
            previous = Path.cwd()
            try:
                os.chdir(scratch)
                Path("Sources/App").mkdir(parents=True)
                Path("Sources/App/Info.plist").write_bytes(plistlib.dumps({"CFBundleShortVersionString": "0.2.7"}))
                with patch.object(release, "api") as remote:
                    with self.assertRaises(ValueError):
                        release.check("example/app", SHA, "v0.2.8")
                    remote.assert_not_called()
                with patch.object(release, "run", return_value="b" * 40), self.assertRaises(ValueError):
                    release.check("example/app", SHA, "v0.2.7")
                with patch.object(release, "run", return_value=SHA), \
                        patch.object(release, "api", return_value={"sha": SHA}), \
                        patch.object(release.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "git")), \
                        self.assertRaises(subprocess.CalledProcessError):
                    release.check("example/app", SHA, "v0.2.7")
            finally:
                os.chdir(previous)

    def test_release_version_is_exact_and_not_a_shell_expression(self):
        self.assertEqual(release.version("v0.2.7"), "0.2.7")
        for tag in ("v0.2.7-beta", "v01.2.7", "0.2.7", "v0.2.7; echo unsafe"):
            with self.assertRaises(ValueError):
                release.version(tag)

    def test_other_commits_branches_and_prs_never_satisfy_the_gate(self):
        for run in (ci(head_sha="b" * 40), ci(head_branch="other"), ci(event="pull_request")):
            self.assertIsNone(release.validate_ci([run], SHA))

    def test_latest_ci_must_finish_successfully(self):
        self.assertIsNone(release.validate_ci([ci(status="queued")], SHA))
        with self.assertRaises(ValueError):
            release.validate_ci([ci(), ci(id=2, conclusion="failure")], SHA)
        self.assertEqual(release.validate_ci([ci()], SHA), 1)

    def test_both_required_jobs_must_pass(self):
        good = [{"name": n, "conclusion": "success"}
                for n in ("macos", "macos-harness", "macos-openconnect", "rust-linux")]
        release.validate_jobs(good)
        for jobs in (good[:1], good[:3], good[:3] + [{"name": "rust-linux", "conclusion": "skipped"}]):
            with self.assertRaises(ValueError):
                release.validate_jobs(jobs)


def pr(**changes):
    return dict({"id": 5, "head_sha": "h" * 40, "event": "pull_request", "head_branch": "feature",
                 "status": "completed", "conclusion": "success"}, **changes)


class SameCodeTests(unittest.TestCase):
    """§47.4: a release may use its pull request's CI only for the same code."""

    def same(self, runs, trees=None, holds=True):
        trees = trees or {SHA: "t", "h" * 40: "t"}
        return release.same_code_pr_run(runs, SHA, trees.get, lambda head: holds)

    def test_the_pull_request_run_of_the_same_code_counts(self):
        self.assertEqual(self.same([pr()]), 5)

    def test_other_code_failures_unfinished_runs_and_pushes_never_count(self):
        self.assertIsNone(self.same([pr()], trees={SHA: "t", "h" * 40: "other"}))
        self.assertIsNone(self.same([pr()], holds=False))
        self.assertIsNone(self.same([pr(conclusion="failure")]))
        self.assertIsNone(self.same([pr(status="in_progress", conclusion=None)]))
        self.assertIsNone(self.same([pr(event="push")]))
        self.assertIsNone(self.same([pr()], trees={"h" * 40: "t"}))  # the tag's tree unknown

    def test_the_latest_run_of_a_head_decides(self):
        self.assertIsNone(self.same([pr(), pr(id=6, conclusion="failure")]))
        self.assertEqual(self.same([pr(conclusion="failure"), pr(id=6)]), 6)

    def test_only_a_merge_of_a_head_that_already_held_main(self):
        with tempfile.TemporaryDirectory() as scratch:
            def git(*args):
                return subprocess.check_output(["git", "-C", scratch, *args], text=True).strip()
            git("init", "-q", "-b", "main")
            git("config", "user.email", "test@example.com")
            git("config", "user.name", "Test")
            def commit(name):
                Path(scratch, name).write_text(name)
                git("add", name)
                git("commit", "-q", "-m", name)
                return git("rev-parse", "HEAD")
            commit("a")
            git("checkout", "-q", "-b", "feature")
            head = commit("b")
            git("checkout", "-q", "main")
            git("merge", "-q", "--no-ff", "-m", "merge", "feature")
            merge = git("rev-parse", "HEAD")
            commit("c")  # main moves on; a later merge of a stale head
            git("checkout", "-q", "-b", "stale", head)
            stale = commit("d")
            git("checkout", "-q", "main")
            git("merge", "-q", "--no-ff", "-m", "merge stale", "stale")
            stale_merge = git("rev-parse", "HEAD")
            previous = Path.cwd()
            try:
                os.chdir(scratch)
                self.assertTrue(release.holds_main(merge, head))
                self.assertTrue(release.holds_main(head, head))
                self.assertFalse(release.holds_main(stale_merge, stale))
                self.assertFalse(release.holds_main(merge, stale))
                self.assertEqual(release.tree_of(merge), release.tree_of(head))
                self.assertIsNone(release.tree_of("f" * 40))
            finally:
                os.chdir(previous)

    def test_gate_passes_at_once_on_the_same_code_and_waits_otherwise(self):
        with tempfile.TemporaryDirectory() as scratch:
            previous = Path.cwd()
            try:
                os.chdir(scratch)
                Path("Sources/App").mkdir(parents=True)
                Path("Sources/App/Info.plist").write_bytes(plistlib.dumps({"CFBundleShortVersionString": "0.2.7"}))
                jobs = [{"name": n, "conclusion": "success"} for n in ("rust-linux", "macos", "macos-harness", "macos-openconnect")]
                def remote(path, *args):
                    if path.endswith("/commits/v0.2.7"):
                        return {"sha": SHA}
                    if "event=pull_request" in path:
                        return {"workflow_runs": [pr()]}
                    if "/jobs" in path:
                        return {"jobs": jobs}
                    if path.endswith("/pulls"):
                        return [{"base": {"ref": "main"}}]
                    return {"workflow_runs": []}
                with patch.object(release, "run", return_value=SHA + "\n"), \
                        patch.object(release, "api", side_effect=remote), \
                        patch.object(release.subprocess, "run"), \
                        patch.object(release, "tree_of", return_value="t"), \
                        patch.object(release, "holds_main", return_value=True), \
                        patch.object(release.time, "sleep", side_effect=AssertionError("waited")):
                    release.check("example/app", SHA, "v0.2.7")
                with patch.object(release, "run", return_value=SHA + "\n"), \
                        patch.object(release, "api", side_effect=remote), \
                        patch.object(release.subprocess, "run"), \
                        patch.object(release, "tree_of", side_effect=lambda c: c), \
                        patch.object(release, "holds_main", return_value=True), \
                        patch.object(release.time, "sleep", side_effect=RuntimeError("waiting")), \
                        self.assertRaises(RuntimeError):
                    release.check("example/app", SHA, "v0.2.7")  # different code: waits for main
            finally:
                os.chdir(previous)


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.previous = Path.cwd()
        os.chdir(self.scratch.name)
        self.addCleanup(self.scratch.cleanup)
        self.addCleanup(os.chdir, self.previous)
        folder = Path(".local-build")
        folder.mkdir()
        names = ["AlwaysConnect-0.2.7-macos-arm64.zip", "AlwaysConnect-0.2.7-macos-arm64.zip.sha256",
                 "AlwaysConnect-0.2.7-third-party-sources.tar.gz"]
        self.files = [folder / name for name in names]
        for file in self.files:
            file.write_bytes((file.name + " fixture").encode())
        self.draft = {"id": 10, "tag_name": "v0.2.7", "target_commitish": SHA, "draft": True,
                      "assets": [{"name": p.name} for p in self.files], "html_url": "https://github.com/example/app/releases/tag/v0.2.7"}
        self.pages = [[]]
        self.calls = []
        self.corrupt = False
        self.tag_sha = SHA
        self.api_patch = patch.object(release, "api", side_effect=self.api)
        self.run_patch = patch.object(release, "run", side_effect=self.command)
        self.api_patch.start()
        self.run_patch.start()
        self.addCleanup(self.api_patch.stop)
        self.addCleanup(self.run_patch.stop)

    def api(self, path, method="GET", payload=None):
        self.calls.append((method, path))
        if "/commits/" in path:
            return {"sha": self.tag_sha}
        if method == "PATCH":
            self.draft["draft"] = payload["draft"]
        return copy.deepcopy(self.draft)

    def command(self, *args, data=None):
        self.calls.append(args)
        if args[:2] == ("gh", "api"):
            return json.dumps(self.pages)
        if args[:3] == ("gh", "release", "download"):
            folder = Path(args[args.index("--dir") + 1])
            for p in self.files:
                (folder / p.name).write_bytes(b"tampered" if self.corrupt else p.read_bytes())
        return ""

    def publish(self):
        release.publish("example/app", SHA, "v0.2.7")

    def test_valid_assets_are_downloaded_before_publication(self):
        self.publish()
        download = next(i for i, c in enumerate(self.calls) if c[:3] == ("gh", "release", "download"))
        publish = next(i for i, c in enumerate(self.calls) if c[0] == "PATCH")
        self.assertLess(download, publish)
        self.assertFalse(self.draft["draft"])

    def test_corrupt_download_never_publishes(self):
        self.corrupt = True
        with self.assertRaises(ValueError):
            self.publish()
        self.assertTrue(self.draft["draft"])
        self.assertFalse(any(c[0] == "PATCH" for c in self.calls))

    def test_published_release_and_unrelated_draft_are_never_overwritten(self):
        for changes in ({"draft": False}, {"target_commitish": "b" * 40}):
            self.pages = [[dict(self.draft, **changes)]]
            with self.assertRaises(ValueError):
                self.publish()
        self.assertFalse(any(c[:3] == ("gh", "release", "upload") for c in self.calls))

    def test_retry_same_commit_draft_is_allowed(self):
        self.pages = [[copy.deepcopy(self.draft)]]
        self.publish()
        self.assertFalse(self.draft["draft"])

    def test_older_version_cannot_replace_latest(self):
        self.pages = [[dict(self.draft, draft=False, tag_name="v0.3.0")]]
        with self.assertRaises(ValueError):
            self.publish()
        self.assertFalse(any(c[:3] == ("gh", "release", "upload") for c in self.calls))

    def test_changed_tag_or_extra_asset_never_publishes(self):
        self.tag_sha = "b" * 40
        with self.assertRaises(ValueError):
            self.publish()
        self.tag_sha = SHA
        self.draft["assets"].append({"name": "unexpected.zip"})
        with self.assertRaises(ValueError):
            self.publish()
        self.assertTrue(self.draft["draft"])


if __name__ == "__main__":
    unittest.main()
