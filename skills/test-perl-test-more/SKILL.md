---
name: test-perl-test-more
description: "How to write a probe as a Test::More script that emits the oracle markers."
---

# Probes in Test::More

- Place the file at `t/harness_probe_<id>.t`. Add `use lib 'lib';` so it can load the modules.
- Inline the nonce. Print markers to STDOUT; the plan does not depend on `ok()` results.

```perl
use strict; use warnings;
use lib 'lib';
use Test::More;
use MyModule qw(target_callable);

my $NONCE = '<nonce>';
my $payload = build_input($NONCE);                 # per the cwe-* skill
print "HARNESS_PRECONDITION::$NONCE\n";            # reached the sink
my $result = target_callable($payload);
print "HARNESS_ORACLE::$NONCE\n" if exploit_condition_holds($result, $NONCE);
done_testing();
```

- Run with `prove -v {test_file}`.
- For a canary oracle, let the payload create `/tmp/harness_canary_<nonce>`; skip the print.
