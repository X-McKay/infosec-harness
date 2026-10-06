package Responder;
use strict;
use warnings;

# Build the raw HTTP response headers for a redirect to $location.
# VULNERABLE: $location is interpolated into the header block with its CR/LF intact,
# so a value containing \r\n injects additional headers and can split the response.
sub redirect_headers {
    my ($location) = @_;
    return "HTTP/1.1 302 Found\r\nLocation: $location\r\nContent-Length: 0\r\n\r\n";
}

1;
