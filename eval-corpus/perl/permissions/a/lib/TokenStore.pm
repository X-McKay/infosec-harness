package TokenStore;
use strict;
use warnings;

# Persist a user's API token to a file under the given directory.
# VULNERABLE: the umask is cleared and the file is made world-readable and writable (0666),
# so any local account can read the token or replace it.
sub save_token {
    my ($dir, $user, $token) = @_;
    my $path = "$dir/$user.token";
    my $old = umask 0;
    open(my $fh, '>', $path) or die "cannot write $path: $!";
    print {$fh} $token;
    close $fh;
    chmod 0666, $path;
    umask $old;
    return $path;
}

1;
