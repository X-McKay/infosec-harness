package Runner;
use strict;
use warnings;

# Run a command.
sub run {
    my ($arg) = @_;
    open(my $fh, '-|', 'echo', $arg) or die "cannot run echo: $!";
    my $out = do { local $/; <$fh> };
    close $fh;
    return $out;
}

1;
