use strict;
use warnings;
use Test::More tests => 3;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Auth;

# The deployed configuration sets admin's real password to a nonce.
my %config = ( admin => 'deployed-nonce-password', alice => 'alice-pw' );

# positive control: the configured credential authenticates.
ok( Auth::authenticate(\%config, 'alice', 'alice-pw'), 'configured user authenticates' );

# negative control: a wrong password is rejected.
ok( !Auth::authenticate(\%config, 'alice', 'wrong'), 'wrong password rejected' );

# VULNERABLE: the hard-coded admin password is accepted even though config set a
# different one.
ok(
    Auth::authenticate(\%config, 'admin', 'S3cr3t-Admin-2024'),
    'hard-coded admin password is accepted by the login path'
);
