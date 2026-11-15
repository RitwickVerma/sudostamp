"""Unit tests for tools/ask.py: the parts that decide what an agent is told before anything is
asked (the end-to-end test in e2e.sh runs the rest against a real sudo and the mock phone)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import ask  # noqa: E402

BLOCK = """#%PAM-1.0
# >>> SudoStamp >>> managed by tools/install.sh; 'install.sh rollback' removes it
auth       [success=ignore ignore=ignore default=1]  pam_exec.so quiet /usr/local/sbin/sudostamp-probe phone=[fd00::5]:7777 keys=/etc/authorized_keys
auth       sufficient   /usr/lib/security/pam_rssh.so ssh_agent_addr=[fd00::5]:7777 auth_key_file=/etc/authorized_keys/${user}.keys cue
# <<< SudoStamp <<<
auth include system-auth
"""


class Block(unittest.TestCase):
    def test_reads_the_probe_line(self):
        self.assertEqual(ask.block_settings(BLOCK), ("[fd00::5]:7777", "/etc/authorized_keys"))

    def test_openpam_has_only_the_rssh_line(self):
        t = "# >>> SudoStamp >>> x\nauth sufficient pam_rssh.so ssh_agent_addr=10.0.0.2:7777 x\n# <<< SudoStamp <<<\n"
        self.assertEqual(ask.block_settings(t), ("10.0.0.2:7777", "/etc/authorized_keys"))

    def test_no_block_or_a_broken_one_is_none(self):
        self.assertIsNone(ask.block_settings("auth include system-auth\n"))
        self.assertIsNone(ask.block_settings("# >>> SudoStamp >>> x\nauth x phone=1.2.3.4:7777\n"))

    def test_lines_outside_the_block_do_not_count(self):
        t = "auth x phone=6.6.6.6:7777\n" + BLOCK
        self.assertEqual(ask.block_settings(t)[0], "[fd00::5]:7777")


class Pause(unittest.TestCase):
    def test_semantics_match_the_probe(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "paused")
        self.assertFalse(ask.paused(0, 1000, p))                     # missing
        for content, expected in [(b"", True), (b"  \n", True), (b"2000", True), (b"999", False),
                                  (b"1000", False), (b"x", False), (b"12abc", False),
                                  (b"1" * 13, False), (b" " * 40, False)]:
            with open(p, "wb") as f:
                f.write(content)
            self.assertEqual(ask.paused(0, 1000, p), expected, content)
        os.unlink(p)
        os.mkdir(p)                                                  # not a regular file
        self.assertFalse(ask.paused(0, 1000, p))


class Build(unittest.TestCase):
    class A:
        script = None
        command = []

    def test_a_command_is_quoted_and_execd(self):
        a = self.A()
        a.command = ["echo", "a b", "$HOME;rm"]
        self.assertEqual(ask.build(a), b"exec echo 'a b' '$HOME;rm'\n")

    def test_refuses_both_neither_empty_and_huge(self):
        a = self.A()
        with self.assertRaises(ask.Stop):
            ask.build(a)
        d = tempfile.mkdtemp()
        for body in (b"  \n", b"x" * (ask.MAX + 1)):
            p = os.path.join(d, "s")
            with open(p, "wb") as f:
                f.write(body)
            a.script = p
            with self.assertRaises(ask.Stop) as c:
                ask.build(a)
            self.assertEqual(c.exception.code, ask.USAGE)
        a.command = ["true"]
        with self.assertRaises(ask.Stop):
            ask.build(a)


class Output(unittest.TestCase):
    """sudo prints PAM messages (pam_rssh's cue) on stdout: they must never reach what the agent
    reads as the script's output. A stand-in for sudo and the runner says exactly what they say."""

    SHA = "ab" * 32
    FAKE = ("printf 'SudoStamp-approve-on-your-phone-(up-to-60s)\\n'; "
            "echo 'sudostamp-run: waiting {sha}' >&2; cat > /dev/null; "
            "echo 'sudostamp-run: approved {sha}' >&2; "
            "printf 'sudostamp-run: output {sha}\\n'; printf 'real output\\n'; exit 3")

    def go(self, capture):
        import io
        argv = ["sh", "-c", self.FAKE.format(sha=self.SHA), "sh", self.SHA]
        so, se = io.BytesIO(), io.StringIO()
        approved, rc, out, _, timed_out = ask.run(argv, b"echo x\n", 10, 10, capture, se, so)
        self.assertTrue(approved)
        self.assertFalse(timed_out)
        self.assertEqual(rc, 3)
        self.assertIn("approve-on-your-phone", se.getvalue())
        return out, so.getvalue()

    def test_streamed_output_is_the_scripts_alone(self):
        out, streamed = self.go(False)
        self.assertEqual((out, streamed), (b"", b"real output\n"))

    def test_captured_output_is_the_scripts_alone(self):
        out, streamed = self.go(True)
        self.assertEqual((out, streamed), (b"real output\n", b""))


class Runner(unittest.TestCase):
    def test_its_python_has_no_single_quote(self):
        # sudostamp-run.sh is `exec python3 -I -S -c '<program>'`: one apostrophe in a comment ends
        # the quoted program and the runner fails to start (it happened).
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sudostamp-run.sh")
        s = open(path).read()
        start = s.index("exec python3 -I -S -c '") + len("exec python3 -I -S -c '")
        self.assertEqual(s[start:s.rindex("' \"$@\"")].count("'"), 0)


class Args(unittest.TestCase):
    def test_bad_agent_and_why_are_usage_errors(self):
        if os.geteuid() == 0:
            self.skipTest("ask refuses root first")
        for argv in (["--agent", "Bad", "--why", "x", "--", "true"], ["--why", "a\nb", "--", "true"],
                     ["--", "true"], ["--why", "x" * 301, "--", "true"]):
            self.assertEqual(ask.main(argv), ask.USAGE, argv)


if __name__ == "__main__":
    unittest.main()
