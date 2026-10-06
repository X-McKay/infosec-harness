package Auth;
use strict;
use warnings;

sub authenticate {
    my ($config, $user, $password) = @_;
    return 0 unless defined $config->{$user};
    return $config->{$user} eq $password ? 1 : 0;
}

1;
