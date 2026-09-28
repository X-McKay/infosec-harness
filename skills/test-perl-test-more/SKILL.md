---
name: test-perl-test-more
description: How to write a probe as a Test::More script that emits the oracle markers. Use this when
  authoring or repairing a probe for a Perl repository.
metadata:
  owner: appsec
  version: 1.0.0
---

# Probes in Test::More

<!-- generated: activation criteria (scripts/restructure_skills.py) -->

## Use this skill when

- You are writing or repairing a probe and the repository's test framework is Test::More or Test2.

## Do not use this skill when

- The repository uses a different framework; load that `test-*` skill.
- You have not yet read `probe-oracle-protocol`; read it first.

<!-- /generated: activation criteria -->

- Place the file at `t/harness_probe_<id>.t`. Add `use lib 'lib';` so it can load the modules.
- Inline the nonce. Print markers to STDOUT; the verdict does not depend on `ok()` results.
- **Always end with `done_testing();`** (or declare `use Test::More tests => N;` up front). A
  `.t` file with no plan makes `prove` report a bad plan and exit nonzero however well the
  probe behaved, which the harness reads as a probe defect.

```perl
use strict; use warnings;
use lib 'lib';
use Test::More;
use MyModule qw(target_callable);

my $NONCE = '<nonce>';
my $payload = build_input($NONCE);                 # per the cwe-* skill
print "HARNESS_PRECONDITION::$NONCE\n";            # about to call the sink
my $result = eval { target_callable($payload) };   # the real sink owner
if ($@) {
    # The target refused the input: that is the code deciding, and it is a negative.
    print "HARNESS_SINK_RETURNED::$NONCE\n" if is_a_rejection($@);
    diag("sink raised: $@");
} else {
    print "HARNESS_SINK_RETURNED::$NONCE\n";        # the call produced an outcome
    print "HARNESS_ORACLE::$NONCE\n" if exploit_condition_holds($result, $NONCE);
}
done_testing();                                    # never omit this
```

- Run with `prove -v {test_file}` — `prove` discards its child's non-TAP output unless verbose,
  so without `-v` none of these markers reaches the harness.
- For a canary oracle, let the payload create `/tmp/harness_canary_<nonce>`; skip the print.

## Never skip

**Do not call `plan skip_all`, `skip_all =>`, `skip`, or `skip_rest` anywhere in a probe.** A
skipped script prints no markers at all, so `prove` reports `skipped: (no reason given)` with
0 tests executed and the harness cannot distinguish it from a probe that is broken: probe
repair is handed a correct probe to fix and burns its whole budget. One Perl command-injection
case was lost this way.

Guarding a probe with `eval { require DBI; 1 } or plan skip_all => '...'` is ordinary,
well-mannered Perl — and wrong here. A module the probe needs being absent is an **environment**
defect, not a reason to decline. Let the `use`/`require` fail so the run exits nonzero with the
module name in its output; that is the signal build repair can act on by installing it. The
probe's job is to report what it observed, and "I chose not to look" is not an observation.

<!-- generated: constraints (scripts/restructure_skills.py) -->

## Safety constraints

- The test must run to completion and print its markers whether or not the exploit condition holds. Never let an assertion failure be the signal.
- Confine every effect to the sandbox temp dir. The probe has no network.
- Do not mock, stub, or reimplement the sink: call the smallest real callable that owns it.

## Completion criteria

- The probe prints the precondition marker at the moment it reaches the sink call.
- It emits the oracle signal only when the exploit condition actually holds.
- It runs to completion and exits cleanly either way.
- Framework output is not captured away, so the markers reach the runner's stdout.
- The probe cannot decline to run: no skip, no disable, no assumption guard. A skipped test prints no markers, which the harness cannot distinguish from a broken probe, so probe repair is handed a correct probe and exhausts its budget on it.

<!-- /generated: constraints -->
