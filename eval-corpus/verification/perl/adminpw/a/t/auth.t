use strict;
use warnings;
use Test::More tests => 3;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Auth;

# The deployed configuration sets admin's real password to a nonce.
my %config = ( admin => 'deployed-nonce-password', alice => 'alice-pw' );

# positive control: the configured admin credential authenticates.
ok( Auth::authenticate(\%config, 'admin', 'deployed-nonce-password'), 'configured admin authenticates' );

# negative control: a wrong password is rejected.
ok( !Auth::authenticate(\%config, 'admin', 'wrong'), 'wrong password rejected' );

# Login as admin with the literal password.
ok(
    !Auth::authenticate(\%config, 'admin', 'S3cr3t-Admin-2024'),
    'admin login with the literal password'
);
