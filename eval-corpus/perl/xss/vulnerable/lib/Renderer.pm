package Renderer;
use strict;
use warnings;
use Exporter 'import';
our @EXPORT_OK = qw(render);

# Render a comment into HTML. VULNERABLE: no output encoding.
sub render {
    my ($text) = @_;
    return "<div class='comment'>" . $text . "</div>";
}

1;
