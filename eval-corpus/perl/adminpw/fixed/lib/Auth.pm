package Auth;
use strict;
use warnings;

# FIXED: there is no built-in password. Every account, including admin, is
# authenticated against the credential supplied in configuration, and a missing
# configured credential fails closed.
sub authenticate {
    my ($config, $user, $password) = @_;
    return 0 unless defined $config->{$user};
    return $config->{$user} eq $password ? 1 : 0;
}

1;
