# `canfail`

[![PyPI](https://img.shields.io/pypi/v/canfail?label=PyPI&color=3775A9)](https://pypi.org/project/canfail/)
[![ci](https://github.com/Megapixel99/canfail/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Megapixel99/canfail/actions/workflows/ci.yml)
[![license MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Break the thing on purpose, and check that your check notices.

**A CI guard that has never failed may be incapable of failing.** A lint rule disabled by
a config merge, a type check whose glob stopped matching, a schema validation step
pointed at the wrong directory, a security scanner with an empty ruleset — every one of
them is green forever, and green is what you were looking for.

```sh
canfail canfail.json
```

```
FINDINGS — 2:
  BLIND    unit tests / label: upper -> lower — the check still PASSED with src/prices.py
           broken — this guard cannot see this defect
  WRONG    unit tests / a break that only breaks the syntax — the check failed on a SYNTAX
           error, which every check does — this break made the file unparseable and tested nothing

LOOK — 1, which never fail the run:
  look     unit tests / an anchor that no longer exists — the anchor matches 0 times in
           src/prices.py and must match exactly once — nothing would have been broken

CAUGHT — 1:
  catches  unit tests / total: multiply -> add — broke src/prices.py, the check went red

4 declared break(s): 1 caught, 2 not caught, 1 not settled
```

That run is `example/`, and it is four outcomes from four declared breaks.

## Configuration

```json
{
  "checks": [
    {
      "name": "unit tests",
      "run": ["python3", "example/test_prices.py", "-q"],
      "breaks": [
        { "name": "total: multiply -> add",
          "file": "example/src/prices.py",
          "replace": "item[\"price\"] * item[\"quantity\"]",
          "with":    "item[\"price\"] + item[\"quantity\"]",
          "expect":  "assert|Error" }
      ]
    }
  ]
}
```

`run` is a command (a list, or a string for a shell). `expect` is optional and is the
third question below.

## Four ways to get this wrong, all borrowed

This is a mutation harness — a very small one, for CI configuration rather than for
code — so it inherits the four properties that make one trustworthy.

**1. The check must pass on the clean tree first.** A check that is already red tells you
nothing when you break something: it was red before and it is red now. Every break under
such a check is a `look`, with the failing line quoted.

**2. A failure is not a catch.** The check has to fail *for the reason you named*. A break
that makes the file unparseable makes every check fail, and that reads as "caught" when
nothing was caught — so a failure whose output looks like a syntax error is scored
`wrong-failure`, as is one that does not match your `expect`.

**3. The anchor must match exactly once.** Zero means the break never happened and the
check passed for the most boring possible reason. Two means the first occurrence was
edited, which may not be the one you meant, so the check was asked about code nobody was
thinking of. Both are `look`, and the message says which.

**4. The file must come back, and the restore must be checked.** This deliberately breaks
source on disk. `finally` does not run on SIGTERM — a test spawns a real child, kills it,
and asserts the source is back — and a restore that *ran* is not a restore that *worked*,
so the digest is compared afterwards. That is [`restore-verified`](../../restore-verified),
which this package **depends on** rather than copies. It used to be 78 lines of `_Guard`
inline — a quarter of the module — carried so `canfail` had no dependencies at all. That
was right while `restore-verified` was unpublished and wrong afterwards: those properties
are exactly what that package is tested hardest on, and a second copy is a second thing to
get wrong. `restore_mtime=False` is passed deliberately; see the bytecode note below.

## `evidence`: telling a blind guard from an absent one

`blind` means two different things unless you say otherwise — *"the check ran and did not
notice"* and *"the check never ran at all"*. The first says your guard is weak; the
second says it is missing, and they send you to opposite ends of the CI file.

Declare `evidence` on a check and [`didrun`](https://github.com/Megapixel99/didrun)
separates them:

```jsonc
{ "name": "unit tests",
  "run": ["python3", "example/test_prices.py", "-q"],
  "evidence": { "count": "Ran (\\d+) tests" },   // what proves it ran at all
  "breaks": [ ... ] }
```

Then a break that stops the check from running is a `look` rather than a finding:

```
look  a break that only breaks the syntax — the check produced no evidence it ran
      against the break (nothing in output matched Ran (\d+) tests, so no count was
      reported at all), so this settles nothing about whether it would have noticed
```

That is also the strong form of rule 2 below. Grepping the output for the word "syntax"
*guesses* at what happened; an evidence predicate **measures** it — a check that never
reached its own tally did not run, whatever it printed on the way out, and in a language
whose parse error uses words the regex has never heard of.

`evidence` is optional and every existing config keeps working. Omit it and `blind` says
outright that it cannot tell the two apart, rather than quietly picking one.

## The verdicts

| verdict | means | fails the run |
|---|---|---|
| `catches` | broke it, the check went red as declared | no |
| `blind` | the check **ran** and still passed with the thing broken | **yes** |
| `wrong-failure` | it failed, but on syntax or not on `expect` | **yes** |
| `look` | baseline red, anchor not exactly once, check would not run | no |

Exit 0 when every declared break was caught, 1 on any finding, 2 when the tool could not
run. The denominator is always printed: a config with no breaks and a config whose every
break was caught otherwise print the same thing, and they are not the same result.

## A bug this found in itself, worth repeating

The first working version reported a genuinely blind guard as **catching**, but only when
it ran second.

After the first break, Python had written `__pycache__/mod.pyc` from the *broken* source.
The second break's run then executed that stale bytecode, so the suite failed for the
previous break's reason and the blind guard looked fine.

The first fix was to stop restoring mtime. **Mutation testing showed that fix does
nothing.** Re-enabling bytecode caching breaks the ordering test whether or not mtime is
restored, because **mtime invalidation has one-second granularity** and this tool edits,
runs and restores in milliseconds — a `.pyc` written from the broken source looks fresh
either way. `PYTHONDONTWRITEBYTECODE` is the load-bearing guard; not restoring mtime is a
cheap belt beside it.

The general form is worth carrying: **anything keyed on mtime — bytecode caches, make,
ninja, file watchers — is blind on a sub-second edit cycle.** Note the tension with
`restore-verified`, which restores mtime *on purpose* so a guarded edit does not trigger
a rebuild. Both are right for their own job, and neither is right for both.

Two tests pin it: one asserts the second break is judged on its own, and a control
asserts the same break alone gives the same verdict, so ordering cannot change the
answer.

## Limits

- **You have to write the breaks.** That is the real adoption cost, and no tool can pay
  it for you. For *code* guarded by *tests*, [`gutcheck`](https://www.npmjs.com/package/gutcheck)
  and Stryker generate mutants automatically and you should use them. This is for the
  guards they do not cover: schema validation, security scanners, deploy gates, lint
  configuration, anything where the thing being guarded is not a function.
- **For Python code guarded by a Python test suite, prefer
  [`mutation-testing`](https://pypi.org/project/mutation-testing/).** It runs the same
  loop — declare a mutation, apply it, see whether the suite notices — and it applies
  mutations by swapping the function's `__code__` object, so **source files are never
  modified**. That is a strictly safer design than this one for that case: no restore,
  no signal handling, no digest to verify, because nothing on disk was ever touched.
  Everything in "the file must come back" above is apparatus this package needs *only
  because* it edits real files, which is what buys it YAML, Terraform, Dockerfiles and
  anything else with no `__code__` object to swap. Read that trade before choosing.
- String anchors, not AST matching. Deliberate — the files a CI guard protects are often
  YAML, JSON, Terraform or Dockerfiles, where there is no parser to match against. The
  exactly-once rule is what makes a string anchor safe enough to use.
- One break at a time, restored between each. No parallelism.
- Zero dependencies, Python 3.9+.

## Tests

```sh
python3 -m unittest discover -s tests
```

15 tests, including a real SIGTERM to a real child. Five mutations were applied — skipping
the clean-tree baseline, accepting any anchor count, scoring a syntax failure as a catch,
not verifying the restore, and re-enabling bytecode caching — and each was caught by the
test that should catch it. A sixth (restoring mtime) **survived**, which is how the
paragraph above got corrected.
