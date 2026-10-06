package TokenStore;
use strict;
use warnings;

# Persist a user's API token to a file under the given directory.
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
