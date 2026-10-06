package Responder;
use strict;
use warnings;

# Build the raw HTTP response headers for a redirect to $location.
# FIXED: CR and LF are stripped from $location before it is placed in the header, so
# the value cannot start a new header line or split the response.
sub redirect_headers {
    my ($location) = @_;
    $location =~ s/[\r\n]//g;
    return "HTTP/1.1 302 Found\r\nLocation: $location\r\nContent-Length: 0\r\n\r\n";
}

1;
