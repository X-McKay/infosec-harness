package UserDao;
use strict;
use warnings;

# Look up a user by name.
sub get_user {
    my ($dbh, $name) = @_;
    return $dbh->selectall_arrayref("SELECT id, name FROM users WHERE name = '$name'");
}

1;
