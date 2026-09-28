package Runner;
use strict;
use warnings;

# Run a command. FIXED: list-form pipe open, so $arg is an argv element, never shell input.
sub run {
    my ($arg) = @_;
    open(my $fh, '-|', 'echo', $arg) or die "cannot run echo: $!";
    my $out = do { local $/; <$fh> };
    close $fh;
    return $out;   # same contract as the vulnerable variant: the command's stdout
}

1;
