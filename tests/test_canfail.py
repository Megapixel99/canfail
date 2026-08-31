"""Each verdict, and the controls that make it falsifiable."""

import contextlib
import hashlib
import inspect
import io
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from canfail import load_config, run_check  # noqa: E402
import canfail.core  # noqa: E402
from canfail.cli import main  # noqa: E402
from restore_verified import RestoreFailed  # noqa: E402

SOURCE = textwrap.dedent(
    """\
    def total(items):
        return sum(i["price"] * i["quantity"] for i in items)


    def label(name):
        return name.upper()
    """
)

SUITE = textwrap.dedent(
    """\
    import os, sys, unittest
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from mod import total, label


    class T(unittest.TestCase):
        def test_total(self):
            self.assertEqual(total([{"price": 2, "quantity": 3}]), 6)

        def test_label_runs(self):
            label("ada")          # hollow on purpose: asserts nothing


    unittest.main()
    """
)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="canfail-test-")
        self.mod = os.path.join(self.dir, "mod.py")
        self.suite = os.path.join(self.dir, "suite.py")
        with open(self.mod, "w") as fh:
            fh.write(SOURCE)
        with open(self.suite, "w") as fh:
            fh.write(SUITE)
        self.digest = self._digest()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _digest(self):
        with open(self.mod, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()

    def check(self, breaks, run=None):
        return run_check({
            "name": "suite",
            "run": run or [sys.executable, self.suite, "-q"],
            "breaks": breaks,
        })

    def a_break(self, name, replace, with_, **extra):
        return dict({"name": name, "file": self.mod, "replace": replace,
                     "with": with_}, **extra)


class TheVerdicts(Fixture):
    def test_a_guard_that_notices_is_a_catch(self):
        out = self.check([self.a_break("multiply", 'i["price"] * i["quantity"]',
                                       'i["price"] + i["quantity"]')])
        self.assertEqual([o.verdict for o in out.outcomes], ["catches"])

    def test_a_hollow_test_is_BLIND_and_that_is_the_finding(self):
        out = self.check([self.a_break("label", "return name.upper()",
                                       "return name.lower()")])
        self.assertEqual([o.verdict for o in out.outcomes], ["blind"])
        self.assertIn("still PASSED", out.outcomes[0].detail)
        self.assertEqual(len(out.findings), 1)

    def test_a_break_that_only_breaks_the_syntax_is_not_a_catch(self):
        # Every check fails on an unparseable file, so a red run here is evidence of
        # nothing. Scoring it as a catch is how a harness reports success for a file it
        # never parsed.
        out = self.check([self.a_break("syntax", "def label(name):", "def label(name)")])
        self.assertEqual([o.verdict for o in out.outcomes], ["wrong-failure"])
        self.assertIn("SYNTAX", out.outcomes[0].detail)

    def test_a_failure_that_does_not_match_expect_is_wrong(self):
        out = self.check([self.a_break(
            "multiply", 'i["price"] * i["quantity"]', 'i["price"] + i["quantity"]',
            expect="TypeError")])
        self.assertEqual([o.verdict for o in out.outcomes], ["wrong-failure"])

    def test_a_failure_that_matches_expect_is_a_catch(self):
        # The control for the test above.
        out = self.check([self.a_break(
            "multiply", 'i["price"] * i["quantity"]', 'i["price"] + i["quantity"]',
            expect="AssertionError|FAILED|assert")])
        self.assertEqual([o.verdict for o in out.outcomes], ["catches"])


class TheAnchor(Fixture):
    """An anchor that does not match exactly once tested something else, or nothing."""

    def test_zero_matches_is_a_look_not_a_pass(self):
        out = self.check([self.a_break("absent", "return name.title()", "x")])
        self.assertEqual([o.verdict for o in out.outcomes], ["look"])
        self.assertIn("0 times", out.outcomes[0].detail)
        self.assertIn("nothing would have been broken", out.outcomes[0].detail)

    def test_two_matches_is_a_look(self):
        with open(self.mod, "a") as fh:
            fh.write("\n\ndef other(name):\n    return name.upper()\n")
        out = self.check([self.a_break("ambiguous", "return name.upper()", "x")])
        self.assertEqual([o.verdict for o in out.outcomes], ["look"])
        self.assertIn("2 times", out.outcomes[0].detail)

    def test_exactly_one_is_what_gets_run(self):
        # Without this the two tests above are satisfied by a tool that refuses
        # everything.
        out = self.check([self.a_break("label", "return name.upper()",
                                       "return name.lower()")])
        self.assertNotEqual(out.outcomes[0].verdict, "look")


class TheBaseline(Fixture):
    def test_a_check_already_failing_settles_nothing(self):
        with open(self.mod, "w") as fh:
            fh.write("def total(items):\n    return 0\n\n\ndef label(n):\n    return n\n")
        out = self.check([self.a_break("anything", "return 0", "return 1")])
        self.assertEqual([o.verdict for o in out.outcomes], ["look"])
        self.assertIn("already FAILS on the clean tree", out.outcomes[0].detail)

    def test_no_breaks_declared_is_a_look(self):
        out = self.check([])
        self.assertEqual([o.verdict for o in out.outcomes], ["look"])
        self.assertIn("no breaks declared", out.outcomes[0].detail)


class TheTreeComesBack(Fixture):
    def test_the_file_is_restored_after_every_break(self):
        self.check([
            self.a_break("multiply", 'i["price"] * i["quantity"]',
                         'i["price"] + i["quantity"]'),
            self.a_break("label", "return name.upper()", "return name.lower()"),
        ])
        self.assertEqual(self._digest(), self.digest)

    def test_the_guard_is_asked_NOT_to_restore_mtime(self):
        """The one guard option this tool cannot afford to get wrong, checked directly.

        `TheOrderingBug` below checks the EFFECT, and mutation testing showed it cannot
        see this flag: `PYTHONDONTWRITEBYTECODE` is the load-bearing protection and
        `restore_mtime=False` is the belt beside it. A belt nothing checks is a belt
        that comes off in a refactor.
        """
        self.assertIn(
            "restore_mtime=False", inspect.getsource(canfail.core),
            "the guard is being asked to restore mtime, which makes a bytecode cache "
            "written from the broken source look fresh",
        )

    def test_RestoreFailed_is_the_dependency_s_exception(self):
        # One exception type across both packages, or `except RestoreFailed` around a
        # canfail call would not catch what canfail's guard raises.
        import restore_verified

        self.assertIs(RestoreFailed, restore_verified.RestoreFailed)

    # `restore-verified` owns the tests for the guard ITSELF -- a sabotaged restore, a
    # real child really killed with SIGTERM, the digest compared afterwards. Those ran
    # here while the guard was 78 lines of this repository; they belong to the package
    # that is tested hardest on them, and a second copy is a second thing to keep in
    # step. What stays is the INTEGRATION assertion above: canfail's own use of the
    # guard leaves the tree as it found it.


class EvidenceSeparatesBlindFromAbsent(Fixture):
    """`blind` used to mean two things, and they send you to opposite ends of the CI file.

    "The check ran and did not notice" is a weak guard. "The check never ran" is an
    absent one. Declaring `evidence` on a check is what lets `didrun` tell them apart.
    """

    def setUp(self):
        super().setUp()
        # A checker that prints its count ONLY when the module parses. That is what a
        # real linter does: given something it cannot read, it reports an error rather
        # than a tally, and its exit code alone cannot say which happened.
        self.checker = os.path.join(self.dir, "checker.py")
        with open(self.checker, "w") as fh:
            fh.write(textwrap.dedent(f"""                import ast, sys
                src = open({self.mod!r}).read()
                try:
                    tree = ast.parse(src)
                except SyntaxError as exc:
                    print("checker: cannot read the file:", exc)
                    sys.exit(2)
                n = sum(1 for node in ast.walk(tree)
                        if isinstance(node, ast.FunctionDef))
                print("checked %d functions" % n)
                sys.exit(0 if "upper" in src else 1)
                """))

    def check_with_evidence(self, breaks, evidence):
        return run_check({
            "name": "checker",
            "run": [sys.executable, self.checker],
            "evidence": evidence,
            "breaks": breaks,
        })

    def test_a_check_that_ran_and_missed_it_is_still_BLIND(self):
        # The checker runs, prints its count, and exits 0 because it only looks at
        # `upper`. Breaking `total` is invisible to it — a genuinely blind guard.
        out = self.check_with_evidence(
            [self.a_break("multiply", 'i["price"] * i["quantity"]',
                          'i["price"] + i["quantity"]')],
            {"count": r"checked (\d+) functions"})
        self.assertEqual([o.verdict for o in out.outcomes], ["blind"])
        self.assertNotIn("no `evidence` declared", out.outcomes[0].detail)

    def test_a_check_that_never_RAN_against_the_break_is_a_look_not_BLIND(self):
        # The break makes the file unparseable, so the checker reports an error and
        # never reaches its tally. It had no opportunity to notice anything, and
        # blaming the guard for that would be blaming it for a run that never happened.
        out = self.check_with_evidence(
            [self.a_break("syntax", "def label(name):", "def label(name)")],
            {"count": r"checked (\d+) functions"})
        self.assertEqual([o.verdict for o in out.outcomes], ["look"])
        self.assertIn("no evidence it ran against the break", out.outcomes[0].detail)

    def test_without_evidence_the_same_break_cannot_be_told_apart(self):
        """THE CONTROL, and the reason the edge is worth having.

        Same checker, same break, no `evidence` declared. The old behaviour is intact
        for every existing config — and the message says outright that it cannot
        distinguish the two, rather than quietly picking one.
        """
        out = run_check({
            "name": "checker",
            "run": [sys.executable, self.checker],
            "breaks": [self.a_break("syntax", "def label(name):", "def label(name)")],
        })
        self.assertNotEqual([o.verdict for o in out.outcomes], ["look"])

    def test_a_check_that_never_runs_at_all_settles_nothing(self):
        # The commonest shape in the field: a glob that matches nothing. The check is
        # green on a clean tree and green on a broken one, and neither is informative.
        out = run_check({
            "name": "a check that does nothing",
            "run": [sys.executable, "-c", "pass"],
            "evidence": {"count": r"checked (\d+) functions"},
            "breaks": [self.a_break("label", "return name.upper()",
                                    "return name.lower()")],
        })
        self.assertEqual([o.verdict for o in out.outcomes], ["look"])
        self.assertIn("even on a clean tree", out.outcomes[0].detail)


class TheOrderingBug(Fixture):
    """The bug that made a BLIND guard look like a working one.

    The guard used to restore mtime, so after the first break Python's `__pycache__`
    held bytecode compiled from the BROKEN source and considered it fresh. Every later
    check ran the first break's code, and the second break was scored against it.
    """

    def test_a_later_break_is_judged_on_its_own(self):
        breaks = [
            self.a_break("multiply", 'i["price"] * i["quantity"]',
                         'i["price"] + i["quantity"]'),
            self.a_break("label", "return name.upper()", "return name.lower()"),
        ]
        out = self.check(breaks)
        verdicts = [o.verdict for o in out.outcomes]
        self.assertEqual(
            verdicts, ["catches", "blind"],
            "the second break was judged against the first one's leftovers — check "
            "that mtime is not being restored and bytecode is not being cached",
        )

    def test_the_same_break_alone_gives_the_same_verdict(self):
        # The control: ordering must not change the answer.
        alone = self.check([self.a_break("label", "return name.upper()",
                                         "return name.lower()")])
        self.assertEqual(alone.outcomes[0].verdict, "blind")


class AKillIsNotACatch(Fixture):
    """A check that ran out of time did not go red — it did not finish.

    `didrun` does not RAISE on a timeout: it kills the child and hands back exit 124,
    which every branch that reads a non-zero status as "the check noticed" scores as a
    catch. That is the tool reporting a working guard where there is a hang, which is
    the precise failure it exists to find in other people's CI.
    """

    def setUp(self):
        super().setUp()
        # Prints its evidence, THEN hangs on the broken source. The evidence is printed
        # first on purpose: with no output at all a timeout is indistinguishable from a
        # check that never ran, and it is the case where the predicate IS satisfied that
        # used to come back as `catches`.
        self.hangs = os.path.join(self.dir, "hangs.py")
        with open(self.hangs, "w") as fh:
            fh.write(textwrap.dedent(f"""\
                import sys, time
                src = open({self.mod!r}).read()
                print("checked 1 files", flush=True)
                if "upper" not in src:
                    time.sleep(60)
                sys.exit(0)
                """))

    def a_hanging_check(self, evidence=None):
        check = {
            "name": "hangs on the break",
            "run": [sys.executable, self.hangs],
            "timeout": 2,
            "breaks": [self.a_break("label", "return name.upper()",
                                    "return name.lower()")],
        }
        if evidence:
            check["evidence"] = evidence
        return run_check(check)

    def test_a_check_killed_on_timeout_is_a_look_not_a_catch(self):
        out = self.a_hanging_check({"count": r"checked (\d+) files"})
        self.assertEqual([o.verdict for o in out.outcomes], ["look"])
        self.assertIn("killed after 2s", out.outcomes[0].detail)

    def test_the_same_hang_without_evidence_is_also_a_look(self):
        # THE CONTROL FOR THE CONTROL. The two paths through `_run` used to disagree
        # about the same event: `look` without evidence, `catches` with it. One timeout
        # is one verdict.
        out = self.a_hanging_check()
        self.assertEqual([o.verdict for o in out.outcomes], ["look"])
        self.assertIn("killed after 2s", out.outcomes[0].detail)

    def test_a_check_that_times_out_on_the_CLEAN_tree_has_no_baseline(self):
        with open(self.mod, "w") as fh:
            fh.write("def label(name):\n    return name.lower()\n")
        out = run_check({
            "name": "hangs on everything",
            "run": [sys.executable, self.hangs],
            "timeout": 2,
            "evidence": {"count": r"checked (\d+) files"},
            "breaks": [self.a_break("label", "return name.lower()",
                                    "return name.title()")],
        })
        self.assertEqual([o.verdict for o in out.outcomes], ["look"])
        self.assertIn("did not finish on the clean tree", out.outcomes[0].detail)


class EvidenceIsResolvedWhereTheCheckRuns(unittest.TestCase):
    """`wrote` names a file the CHECK writes, so it is the check's cwd that it is in.

    The predicate stats the path in this process. Resolving it against the config's
    directory instead makes a check that ran perfectly report as never having run, and
    every break under it becomes an unsettled `look`.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="canfail-cwd-")
        os.makedirs(os.path.join(self.dir, "src"))
        with open(os.path.join(self.dir, "src", "mod.py"), "w") as fh:
            fh.write("SPEED = 'fast'\n")
        with open(os.path.join(self.dir, "chk.py"), "w") as fh:
            fh.write(textwrap.dedent("""\
                import sys
                src = open("src/mod.py").read()
                open("report.json", "w").write("{}")
                sys.exit(0 if "fast" in src else 1)
                """))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_a_wrote_predicate_is_relative_to_the_check_s_cwd(self):
        out = run_check({
            "name": "writes a report",
            "run": [sys.executable, "chk.py"],
            "evidence": {"wrote": "report.json"},
            "breaks": [{"name": "fast -> slow", "file": "src/mod.py",
                        "replace": "'fast'", "with": "'slow'"}],
        }, cwd=self.dir)
        self.assertEqual([o.verdict for o in out.outcomes], ["catches"])


class AConfigThatCannotRunIsExit2(unittest.TestCase):
    """A config mistake and a finding must not share an exit status.

    `re.error` is not a `ValueError`, so an uncompilable pattern used to escape every
    `except` here and reach the interpreter — a traceback and exit 1, which is the code
    that means a guard is BLIND. CI branching on the documented exit codes reads that as
    a finding.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="canfail-cfg-")
        self.path = os.path.join(self.dir, "canfail.json")
        with open(os.path.join(self.dir, "mod.py"), "w") as fh:
            fh.write("SPEED = 'fast'\n")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, config):
        import json
        with open(self.path, "w") as fh:
            json.dump(config, fh)
        return self.path

    def a_config(self, **break_extra):
        return {"checks": [{
            "name": "c", "run": [sys.executable, "-c", "pass"],
            "breaks": [dict({"name": "b", "file": os.path.join(self.dir, "mod.py"),
                             "replace": "'fast'", "with": "'slow'"}, **break_extra)],
        }]}

    def test_an_uncompilable_expect_is_rejected_before_anything_is_broken(self):
        with self.assertRaises(ValueError) as caught:
            load_config(self.write(self.a_config(expect="(")))
        self.assertIn("not a valid regular expression", str(caught.exception))

    def test_the_cli_exits_2_on_a_bad_pattern_rather_than_1(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main([self.write(self.a_config(expect="("))])
        self.assertEqual(code, 2, "exit 1 would be indistinguishable from a finding")
        self.assertIn("canfail:", err.getvalue())

    def test_an_evidence_object_that_declares_nothing_is_rejected(self):
        # A misspelled key would otherwise leave the check running in the weak form
        # while the config says otherwise — and the outcome would report "no `evidence`
        # declared" to someone looking straight at the declaration.
        config = self.a_config()
        config["checks"][0]["evidence"] = {"expct": r"Ran (\d+) tests"}
        with self.assertRaises(ValueError) as caught:
            load_config(self.write(config))
        self.assertIn("expct", str(caught.exception))

    def test_omitting_evidence_entirely_is_still_fine(self):
        # The control: the rejection above must be about a typo, not about the absence.
        self.assertEqual(load_config(self.write(self.a_config()))["checks"][0]["name"],
                         "c")


class TheBreakIsTheOnlyEdit(unittest.TestCase):
    """A CRLF file must come out of a break with its line endings intact.

    Universal-newline mode hands back the text with every `\r` stripped, and the guard
    writes that text back verbatim — so a one-line break rewrites every line ending in
    the file, and a formatting guard goes red for a change nobody declared.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="canfail-crlf-")
        self.mod = os.path.join(self.dir, "mod.py")
        with open(self.mod, "wb") as fh:
            fh.write(b"SPEED = 'fast'\r\nOTHER = 1\r\n")
        self.seen = os.path.join(self.dir, "seen.bin")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_only_the_anchor_changes(self):
        chk = os.path.join(self.dir, "chk.py")
        with open(chk, "w") as fh:
            fh.write(textwrap.dedent(f"""\
                import sys
                data = open({self.mod!r}, "rb").read()
                open({self.seen!r}, "wb").write(data)
                sys.exit(0 if b"fast" in data else 1)
                """))
        run_check({
            "name": "reads the bytes",
            "run": [sys.executable, chk],
            "breaks": [{"name": "fast -> slow", "file": self.mod,
                        "replace": "'fast'", "with": "'slow'"}],
        })
        with open(self.seen, "rb") as fh:
            broken = fh.read()
        self.assertEqual(broken, b"SPEED = 'slow'\r\nOTHER = 1\r\n",
                         "the break rewrote the line endings as well as the anchor")


if __name__ == "__main__":
    unittest.main(verbosity=2)
