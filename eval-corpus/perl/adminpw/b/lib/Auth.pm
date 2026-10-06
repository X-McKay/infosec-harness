package Auth;
use strict;
use warnings;

# A hard-coded administrative password compiled into the module.
# VULNERABLE: anyone who can read the source knows this password, and the login path
# accepts it for the "admin" account regardless of any configured credential.
my $ADMIN_PASSWORD = 'S3cr3t-Admin-2024';

# authenticate($config, $user, $password) -> 1 on success, 0 on failure.
# $config maps username => password for ordinary accounts.
sub authenticate {
    my ($config, $user, $password) = @_;
    if ($user eq 'admin') {
        return $password eq $ADMIN_PASSWORD ? 1 : 0;
    }
    return 0 unless exists $config->{$user};
    return $config->{$user} eq $password ? 1 : 0;
}

1;
