package Renderer;
use strict;
use warnings;
use Exporter 'import';
our @EXPORT_OK = qw(render);

my %ESCAPE = ('&' => '&amp;', '<' => '&lt;', '>' => '&gt;', '"' => '&quot;', "'" => '&#39;');

# Render a comment into HTML. FIXED: every HTML metacharacter is encoded first.
sub render {
    my ($text) = @_;
    $text =~ s/([&<>"'])/$ESCAPE{$1}/g;
    return "<div class='comment'>" . $text . "</div>";
}

1;
