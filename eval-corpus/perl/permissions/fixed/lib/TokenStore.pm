package TokenStore;
use strict;
use warnings;
use Fcntl qw(O_CREAT O_WRONLY O_TRUNC);

# Persist a user's API token to a file under the given directory.
# FIXED: the file is created owner-only (0600) under a restrictive umask, and the mode is
# reasserted in case the file already existed.
sub save_token {
    my ($dir, $user, $token) = @_;
    my $path = "$dir/$user.token";
    my $old = umask 077;
    sysopen(my $fh, $path, O_CREAT | O_WRONLY | O_TRUNC, 0600) or die "cannot write $path: $!";
    print {$fh} $token;
    close $fh;
    chmod 0600, $path;
    umask $old;
    return $path;
}

1;
