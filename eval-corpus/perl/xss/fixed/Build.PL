use strict;
use warnings;
use Module::Build;

# A Module::Build distribution whose tests are Test2::V0, not Test::More: the second axis this
# case exists for. `Build.PL` and `Test2::V0` are both things the fingerprint used to miss.
Module::Build->new(
    module_name   => 'Renderer',
    dist_abstract => 'Comment renderer (fixed variant)',
    dist_version  => '1.0.0',
    requires      => { 'Exporter' => 0 },
    test_requires => { 'Test2::V0' => 0 },
)->create_build_script;
