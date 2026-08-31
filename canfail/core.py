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

  2c. AND A KILL IS NEITHER. A check that ran out of time did not go red; it did not
     finish. `didrun` catches the timeout and hands back exit 124 rather than raising,
     so `killed` -- not the exit status -- is the only thing that can say which happened.
     See `_Ran` below: reading 124 as "the check went red as declared" is how a hang
     gets scored as a catch.

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

# The conventional status for a killed-on-timeout command, as `timeout(1)` uses and as
# `didrun` reports. It is never read as a verdict here -- see `_Ran.killed`.
TIMEOUT_CODE = 124

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

def _regex(pattern, where: str):
    """Compile a caller-supplied pattern, or say WHICH field was not a regex.

    `re.error` is not a `ValueError`, so an uncompilable pattern from a config file
    escapes every `except` in this package and reaches the interpreter as a traceback --
    exit 1, which is the code that means "a guard is BLIND". A config mistake and a
    finding must not share an exit status, so it is re-raised as the config error it is.
    """
    try:
        return re.compile(pattern)
    except (re.error, TypeError) as exc:
        raise ValueError(f"{where} is not a valid regular expression: {exc}") from None


@dataclass
class _Ran:
    """One finished run of a check.

    `killed` is separate from `code` ON PURPOSE. `didrun` does not raise on a timeout --
    it kills the child and reports exit 124 -- and every branch that reads a non-zero
    status as "the check noticed" would score a hang as a catch. A killed check did not
    go red; it did not finish, and that settles nothing either way.
    """

    code: int
    output: str
    state: object = None
    why: str = ""
    killed: bool = False


def _predicates(spec, cwd=None):
    """`didrun` predicates from a check's `evidence`, or [] when none was declared.

    A string is the common case and means "the output must match this". The object form
    exists for the one that matters: a COUNT, because what makes a green run meaningless
    is almost always a zero rather than an absence.

    `wrote` is resolved against `cwd`, the directory the check itself runs in. The
    predicate stats the path in THIS process, so a bare `report.json` would otherwise be
    looked for beside the config while the check writes it beside itself, and the miss
    reads as "the check never ran" for a check that ran perfectly.
    """
    if not spec:
        return []
    if isinstance(spec, str):
        return [ev.matches(_regex(spec, "`evidence`"))]
    if not isinstance(spec, dict):
        raise ValueError(
            f"`evidence` must be a string or an object, not {type(spec).__name__}")
    out = []
    if "count" in spec:
        out.append(ev.count(_regex(spec["count"], "`evidence.count`"),
                            minimum=int(spec.get("min", 1))))
    if "expect" in spec:
        out.append(ev.matches(_regex(spec["expect"], "`evidence.expect`")))
    if "wrote" in spec:
        out.append(ev.wrote(os.path.join(cwd, spec["wrote"]) if cwd else spec["wrote"]))
    if not out:
        # SILENTLY FALLING BACK IS THE FAILURE THIS PACKAGE IS ABOUT. A misspelled key
        # would leave a check running in the weak form while its config says otherwise,
        # and the outcome would then report "no `evidence` declared" to someone looking
        # straight at the declaration.
        raise ValueError(
            f"`evidence` declares none of `count`, `expect` or `wrote` — it has "
            f"{sorted(spec)!r}. Omitting `evidence` is fine; declaring one that does "
            f"nothing is a typo that would quietly disable the check it was added for")
    return out


def _text(chunk) -> str:
    if chunk is None:
        return ""
    return chunk if isinstance(chunk, str) else chunk.decode(errors="replace")


def _run(command, cwd=None, timeout=DEFAULT_TIMEOUT, predicates=()) -> _Ran:
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
        # `result.killed`, NOT `result.code`. `didrun` catches the timeout itself and
        # reports exit 124, which reads exactly like a check that went red.
        return _Ran(result.code, result.stdout + result.stderr, result.state, why,
                    result.killed)
    try:
        if isinstance(command, str):
            proc = subprocess.run(command, shell=True, cwd=cwd, capture_output=True,
                                  text=True, timeout=timeout, env=env)
        else:
            proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                  timeout=timeout, env=env)
    except subprocess.TimeoutExpired as expired:
        # The same shape the evidence path returns, so a timeout means ONE thing here
        # whether or not `evidence` was declared. It used to mean two: a `look` without
        # evidence and a `catches` with it, for the same hang.
        return _Ran(TIMEOUT_CODE, _text(expired.stdout) + _text(expired.stderr),
                    killed=True)
    # No evidence declared, so nothing here can speak to whether it ran.
    return _Ran(proc.returncode, (proc.stdout or "") + (proc.stderr or ""))


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

    if "run" not in check:
        raise ValueError(f"the check {name!r} has no `run`")
    predicates = _predicates(check.get("evidence"), cwd)

    def every_break(detail):
        for br in breaks:
            report.outcomes.append(Outcome(name, br.get("name", "?"), "look", detail))
        return report

    # (1) THE BASELINE. Without it a red check looks like a working one.
    try:
        ran = _run(check["run"], cwd, timeout, predicates)
    except OSError as exc:
        return every_break(f"the check could not be run on the clean tree ({exc})")
    if ran.killed:
        # BEFORE EVERYTHING ELSE. A check that does not finish on a CLEAN tree has no
        # baseline at all, and its exit status is the timeout's rather than its own.
        return every_break(
            f"the check did not finish on the clean tree — it was killed after "
            f"{timeout}s, so there is no baseline to compare a break against")
    if ran.state == didrun.DID_NOT_RUN:
        # BEFORE "it already fails", because this is the stronger objection. A check
        # that produces no evidence of running on a CLEAN tree will produce none on a
        # broken one either, and every verdict after this point would be an artefact of
        # a command that did nothing.
        return every_break(
            f"the check produced no evidence it ran, even on a clean tree — "
            f"{ran.why} — so breaking something can prove nothing from here")
    if ran.code != 0:
        tail = (ran.output.strip().splitlines() or ["silent"])[-1][:110]
        return every_break(
            f"the check already FAILS on the clean tree (exit {ran.code}: {tail}) — "
            f"breaking something can prove nothing from here")

    for br in breaks:
        report.outcomes.append(_one_break(name, br, check, cwd, timeout, predicates))
    return report


def _one_break(check_name: str, br: dict, check: dict, cwd, timeout,
               predicates=()) -> Outcome:
    br_name = br.get("name") or f"{br.get('file')}:{br.get('replace','')[:24]}"
    path = os.path.join(cwd or ".", br["file"]) if cwd else br["file"]
    if not os.path.exists(path):
        return Outcome(check_name, br_name, "look", f"{br['file']} does not exist")

    # `newline=""` SO THE BREAK IS THE ONLY EDIT. Universal-newline mode would hand back
    # a CRLF file with every `\r` stripped, and the guard writes the text back verbatim
    # -- so on a CRLF checkout the "one-line" break rewrites every line ending in the
    # file, and a formatting guard goes red for a change nobody declared.
    with open(path, encoding="utf-8", newline="") as fh:
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
                ran = _run(check["run"], cwd, timeout, predicates)
            except OSError as exc:
                return Outcome(check_name, br_name, "look",
                               f"the check could not be run against the break ({exc})")
    except RestoreFailed as exc:
        return Outcome(check_name, br_name, "look", str(exc))

    if ran.killed:
        # NOT `catches`. Exit 124 is the timeout's status and not the check's, and a
        # check that was killed never reached a verdict about anything.
        return Outcome(
            check_name, br_name, "look",
            f"the check did not finish against the break — it was killed after "
            f"{timeout}s, so its exit status is the timeout's rather than a verdict "
            f"about the break")

    if ran.state == didrun.DID_NOT_RUN:
        # NOT `blind`. The check did not run against the break, so it had no opportunity
        # to notice -- reporting that as "this guard cannot see this defect" would blame
        # a guard for a run that never happened.
        return Outcome(
            check_name, br_name, "look",
            f"the check produced no evidence it ran against the break ({ran.why}), so "
            f"this settles nothing about whether it would have noticed")

    if ran.code == 0:
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
    if SYNTAX_NOISE.search(ran.output):
        return Outcome(
            check_name, br_name, "wrong-failure",
            "the check failed on a SYNTAX error, which every check does — this break "
            "made the file unparseable and tested nothing")
    expect = br.get("expect")
    if expect and not _regex(expect, f"`expect` on the break {br_name!r}").search(
            ran.output):
        tail = (ran.output.strip().splitlines() or ["silent"])[-1][:110]
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


def load_config(path: str, cwd=None) -> dict:
    """Read a config, and reject one that cannot be run BEFORE anything is broken.

    Every pattern is compiled here rather than at the point of use. A regex that does
    not compile is a config error, and finding it three breaks in -- after files have
    been edited and restored -- turns a typo into a traceback in the middle of a run.
    """
    with open(path, encoding="utf-8") as fh:
        config = json.load(fh)
    if not isinstance(config, dict) or not isinstance(config.get("checks"), list):
        raise ValueError(f"{path} has no `checks` list")
    for check in config["checks"]:
        if not isinstance(check, dict) or "run" not in check:
            raise ValueError("every check needs a `run`")
        _predicates(check.get("evidence"), cwd)
        for br in check.get("breaks", []):
            for key in ("file", "replace", "with"):
                if key not in br:
                    raise ValueError(f"every break needs `{key}`")
            if br.get("expect"):
                where = br.get("name", br["file"])
                _regex(br["expect"], f"`expect` on the break {where!r}")
    return config
