"""Break the thing on purpose, and check that your check notices.

A CI guard that has never failed may be INCAPABLE of failing. A lint rule that was
disabled by a config merge, a type check whose glob stopped matching, a schema
validation step pointed at the wrong directory, a security scanner whose ruleset is
empty — every one of them is green forever, and green is what you were looking for.

The only way to know a guard works is to break the thing it guards and watch it go red.
That is one line to say and four ways to get wrong, and all four are borrowed from
`assay`'s audit of mutation harnesses because this IS a mutation harness — a very small
one, for CI configuration rather than for code:

  1. THE CHECK MUST PASS ON THE CLEAN TREE FIRST. A check that is already failing tells
     you nothing when you break something: it was red before and it is red now.

  2. A FAILURE IS NOT A CATCH. The check has to fail for the reason you named. A break
     that makes the file unparseable makes every check fail, and that reads as "caught"
     when nothing was caught.

  2b. AND A PASS IS NOT A BLINDNESS. This is `didrun`'s question, and without it `blind`
     means two different things: "the check ran and did not notice" and "the check never
     ran at all". They are not the same finding -- the first says your guard is weak, the
     second says your guard is absent, and they send you to opposite ends of the CI
     file. Declare `evidence` on a check and the two are separated. Omit it and they are
     not, and the message says so rather than picking one.

  3. THE ANCHOR MUST MATCH EXACTLY ONCE. An anchor matching zero places is a break that
     never happened, and the check passes for the most boring possible reason. One
     matching twice edits the first occurrence, which may not be the one you meant, so
     the check is asked about code nobody was thinking of.

  4. THE FILE MUST COME BACK, AND THE RESTORE MUST BE CHECKED. This deliberately breaks
     source on disk. `finally` does not run on SIGTERM, and a restore that ran is not a
     restore that worked.

Point 4 is `restore-verified`'s contract, and it is now that package rather than a copy
of it. It used to be 78 lines of `_Guard` inline -- a quarter of this module -- carried
so that `canfail` had no dependencies. That was the right call while `restore-verified`
was unpublished and the wrong one afterwards: the properties in point 4 are exactly what
that package is tested hardest on (a real child, really killed, with the restore checked
by digest), and a second copy of them here is a second thing to get wrong.

`restore_mtime=False` is passed deliberately. See the note on `_run` below: this tool
compiles what it just restored, and mtime cache invalidation is blind on a sub-second
edit cycle.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field

import didrun
from didrun import evidence as ev
from restore_verified import RestoreFailed, guarded

DEFAULT_TIMEOUT = 900

# A break that makes the source unparseable makes EVERY check fail, so a failure that
# looks like this is not evidence the guard works.
#
# THIS IS THE WEAK FORM, and `evidence` is the strong one. Grepping the output for the
# word "syntax" guesses at what happened; a declared `evidence` predicate MEASURES it —
# a check that never reached its own tally did not run, whatever it printed on the way
# out, and in a language whose parse error says something this list has never heard of.
# The regex stays for checks that declare no evidence, which is every existing config.
SYNTAX_NOISE = re.compile(
    r"syntax\s*error|invalid syntax|unexpected token|parse error|cannot parse|"
    r"unterminated|unexpected end of input",
    re.IGNORECASE,
)


@dataclass
class Outcome:
    check: str
    break_name: str
    verdict: str          # "catches" | "blind" | "wrong-failure" | "look"
    detail: str = ""

    def __str__(self) -> str:
        label = {
            "catches": "catches ",
            "blind": "BLIND   ",
            "wrong-failure": "WRONG   ",
            "look": "look    ",
        }[self.verdict]
        return f"  {label} {self.check} / {self.break_name} — {self.detail}"


@dataclass
class Report:
    outcomes: list = field(default_factory=list)

    @property
    def findings(self):
        return [o for o in self.outcomes if o.verdict in ("blind", "wrong-failure")]

    @property
    def looks(self):
        return [o for o in self.outcomes if o.verdict == "look"]

    @property
    def catches(self):
        return [o for o in self.outcomes if o.verdict == "catches"]

    def to_dict(self) -> dict:
        return {
            "breaks": len(self.outcomes),
            "catches": len(self.catches),
            "findings": len(self.findings),
            "look": len(self.looks),
            "outcomes": [vars(o) for o in self.outcomes],
        }


# --------------------------------------------------------------------------- #
# Running checks.
# --------------------------------------------------------------------------- #

def _predicates(spec):
    """`didrun` predicates from a check's `evidence`, or [] when none was declared.

    A string is the common case and means "the output must match this". The object form
    exists for the one that matters: a COUNT, because what makes a green run meaningless
    is almost always a zero rather than an absence.
    """
    if not spec:
        return []
    if isinstance(spec, str):
        return [ev.matches(spec)]
    out = []
    if "count" in spec:
        out.append(ev.count(spec["count"], minimum=int(spec.get("min", 1))))
    if "expect" in spec:
        out.append(ev.matches(spec["expect"]))
    if "wrote" in spec:
        out.append(ev.wrote(spec["wrote"]))
    return out


def _run(command, cwd=None, timeout=DEFAULT_TIMEOUT, predicates=()):
    # `PYTHONDONTWRITEBYTECODE` SO A CHECK DOES NOT LEAVE A CACHE THE NEXT BREAK
    # INHERITS. This is the load-bearing guard, established by mutation rather than by
    # argument: removing it makes a genuinely BLIND guard report as catching, because
    # the second break's run executes bytecode compiled from the first break's source.
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    if predicates:
        # WHEN EVIDENCE IS DECLARED, `didrun` DECIDES WHETHER IT RAN. A shell string is
        # not something `didrun` takes -- it runs an argv -- so it is handed to the
        # shell explicitly, which keeps `run` accepting both spellings it always did.
        argv = ["/bin/sh", "-c", command] if isinstance(command, str) else list(command)
        result = didrun.run(argv, evidence=predicates, timeout=timeout, cwd=cwd, env=env)
        # The unsatisfied predicates, so a `look` can say WHAT was looked for and what
        # was there instead of just "no evidence".
        why = "; ".join(c.detail for c in result.checks if not c.satisfied)
        return result.code, result.stdout + result.stderr, result.state, why
    if isinstance(command, str):
        proc = subprocess.run(command, shell=True, cwd=cwd, capture_output=True,
                              text=True, timeout=timeout, env=env)
    else:
        proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout, env=env)
    # No evidence declared, so nothing here can speak to whether it ran.
    return proc.returncode, (proc.stdout or "") + (proc.stderr or ""), None, ""


def run_check(check: dict, cwd=None) -> Report:
    """One check, against every break declared for it."""
    report = Report()
    name = check.get("name") or str(check.get("run"))
    breaks = check.get("breaks") or []
    timeout = check.get("timeout", DEFAULT_TIMEOUT)

    if not breaks:
        report.outcomes.append(Outcome(
            name, "(none)", "look",
            "no breaks declared — a check with nothing to catch is not being tested"))
        return report

    predicates = _predicates(check.get("evidence"))

    # (1) THE BASELINE. Without it a red check looks like a working one.
    try:
        code, output, state, why = _run(check["run"], cwd, timeout, predicates)
    except (subprocess.TimeoutExpired, OSError) as exc:
        for br in breaks:
            report.outcomes.append(Outcome(
                name, br.get("name", "?"), "look",
                f"the check could not be run on the clean tree ({exc})"))
        return report
    if state == didrun.DID_NOT_RUN:
        # BEFORE "it already fails", because this is the stronger objection. A check
        # that produces no evidence of running on a CLEAN tree will produce none on a
        # broken one either, and every verdict after this point would be an artefact of
        # a command that did nothing.
        for br in breaks:
            report.outcomes.append(Outcome(
                name, br.get("name", "?"), "look",
                f"the check produced no evidence it ran, even on a clean tree — "
                f"{why} — so breaking something can prove nothing from here"))
        return report
    if code != 0:
        tail = (output.strip().splitlines() or ["silent"])[-1][:110]
        for br in breaks:
            report.outcomes.append(Outcome(
                name, br.get("name", "?"), "look",
                f"the check already FAILS on the clean tree (exit {code}: {tail}) — "
                f"breaking something can prove nothing from here"))
        return report

    for br in breaks:
        report.outcomes.append(_one_break(name, br, check, cwd, timeout, predicates))
    return report


def _one_break(check_name: str, br: dict, check: dict, cwd, timeout,
               predicates=()) -> Outcome:
    br_name = br.get("name") or f"{br.get('file')}:{br.get('replace','')[:24]}"
    path = os.path.join(cwd or ".", br["file"]) if cwd else br["file"]
    if not os.path.exists(path):
        return Outcome(check_name, br_name, "look", f"{br['file']} does not exist")

    with open(path, encoding="utf-8") as fh:
        original = fh.read()

    # (3) EXACTLY ONCE. Zero is a break that never happened; two is a break somewhere
    # you were not thinking about.
    anchor = br["replace"]
    hits = original.count(anchor)
    if hits != 1:
        # Built before the f-string rather than inside it: a multi-line expression
        # inside an f-string is 3.12 syntax, and `requires-python` here says 3.9. The
        # matrix caught it, which is what a matrix that starts at the declared floor is
        # for -- a floor nothing runs at is a claim, not a constraint.
        consequence = ("nothing would have been broken" if hits == 0 else
                       "the first occurrence would be edited, which may not be the one "
                       "you meant")
        return Outcome(
            check_name, br_name, "look",
            f"the anchor matches {hits} times in {br['file']} and must match exactly "
            f"once — {consequence}")

    try:
        with guarded(path, restore_mtime=False) as guard:
            guard.write(original.replace(anchor, br["with"], 1))
            try:
                code, output, state, why = _run(check["run"], cwd, timeout, predicates)
            except (subprocess.TimeoutExpired, OSError) as exc:
                return Outcome(check_name, br_name, "look",
                               f"the check could not be run against the break ({exc})")
    except RestoreFailed as exc:
        return Outcome(check_name, br_name, "look", str(exc))

    if state == didrun.DID_NOT_RUN:
        # NOT `blind`. The check did not run against the break, so it had no opportunity
        # to notice -- reporting that as "this guard cannot see this defect" would blame
        # a guard for a run that never happened.
        return Outcome(
            check_name, br_name, "look",
            f"the check produced no evidence it ran against the break ({why}), so this "
            f"settles nothing about whether it would have noticed")

    if code == 0:
        # (THE FINDING.) The guard ran and did not notice. That is what this exists to
        # report — and with `evidence` declared it is now the narrow claim rather than
        # the broad one.
        unsure = ("" if predicates else
                  " (no `evidence` declared for this check, so this cannot distinguish "
                  "a guard that ran and missed it from one that never ran)")
        return Outcome(
            check_name, br_name, "blind",
            f"the check still PASSED with {br['file']} broken — this guard cannot see "
            f"this defect{unsure}")

    # (2) A FAILURE IS NOT A CATCH.
    if SYNTAX_NOISE.search(output):
        return Outcome(
            check_name, br_name, "wrong-failure",
            "the check failed on a SYNTAX error, which every check does — this break "
            "made the file unparseable and tested nothing")
    expect = br.get("expect")
    if expect and not re.search(expect, output):
        tail = (output.strip().splitlines() or ["silent"])[-1][:110]
        return Outcome(
            check_name, br_name, "wrong-failure",
            f"it failed, but not with {expect!r} — it said: {tail}")
    return Outcome(check_name, br_name, "catches",
                   f"broke {br['file']}, the check went red as declared")


def run_config(config: dict, cwd=None) -> Report:
    report = Report()
    for check in config.get("checks", []):
        report.outcomes.extend(run_check(check, cwd).outcomes)
    return report


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        config = json.load(fh)
    if not isinstance(config, dict) or "checks" not in config:
        raise ValueError(f"{path} has no `checks` list")
    for check in config["checks"]:
        if "run" not in check:
            raise ValueError("every check needs a `run`")
        for br in check.get("breaks", []):
            for key in ("file", "replace", "with"):
                if key not in br:
                    raise ValueError(f"every break needs `{key}`")
    return config
