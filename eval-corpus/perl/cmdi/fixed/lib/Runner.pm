package Runner;
use strict;
use warnings;

# Run a command. FIXED: list form, no shell.
sub run {
    my ($arg) = @_;
    system('echo', $arg);
    return $? >> 8;
}

1;
