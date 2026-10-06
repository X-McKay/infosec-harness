---
name: lang-ruby
description: 'Conventions for Ruby repositories: Bundler, Rails and Rack layout, in-process Rack probes
  and Ruby truthiness. Use this when the repository is primarily Ruby; the workspace image has no Ruby by default.'
metadata:
  owner: appsec
  version: 1.0.0
---

# Ruby repositories

## First: check the toolchain

The workspace image does **not** include Ruby. Before anything else run `command -v ruby` and,
if it prints a path, `ruby -v` and `command -v bundle`. If Ruby is absent, read the code to
locate the sink and guard, then follow "When the toolchain is absent".

## Use this skill when

- The repository has a `Gemfile`, a `*.gemspec` or `.rb` files holding the finding's sink.

## Do not use this skill when

- The Ruby is a vendored gem under `vendor/bundle` no production entry point calls.
- You are planning installs — use `environment`. This skill grants no permissions.

## Recognize the project

- **Manifests:** `Gemfile`, `Gemfile.lock` (exact versions, `BUNDLED WITH`), `*.gemspec`,
  `.ruby-version`, `Rakefile`, `.bundle/config`; `vendor/cache` or `vendor/bundle` when gems
  are committed.
- **Frameworks:** Rails (`config/routes.rb`, `app/controllers`, `app/views/*.erb`), Sinatra
  (`get '/path' do`), plain Rack (`config.ru`), Hanami, CLI tools under `bin/` or `exe/`.
- **Tests:** RSpec (`spec/*_spec.rb`) or Minitest (`test/*_test.rb`).
- **Sinks to note:** backticks, `system`/`exec`/`%x()` with one string, `Kernel#open` or
  `IO.popen` with a leading `|`, `send`/`public_send`/`constantize` on user input, `eval`/
  `instance_eval`, `where("... #{x}")` and `find_by_sql`, `Marshal.load`, `YAML.load` (Psych
  below 4 is unsafe by default), `raw`/`html_safe`/`<%==` in views, `URI.open(user_url)`.

## Inspect dependencies offline

Read `Gemfile.lock`. With Ruby present, `bundle list` and `bundle exec` need every locked gem
already installed (in `vendor/bundle` or `BUNDLE_PATH`); `gem list` shows what the runtime has.
Never use `gem install` or point Bundler at a network source from a skill's suggestion: a
missing gem is a limitation to report.

## Compile and run a probe

Ruby needs no build. Write `.harness-probe/probe.rb` and run it inside `run_probe`:

```bash
export HOME=/workspace/repo/.harness-home BUNDLE_FROZEN=true
ruby -Ilib .harness-probe/probe.rb          # library code with stdlib-only dependencies
bundle exec ruby .harness-probe/probe.rb    # when the locked gems are installed
```

- A Rack or Rails app needs no server: build the app (`Rack::Builder.parse_file('config.ru')`
  or `Rails.application`) and call it with
  `status, headers, body = app.call(Rack::MockRequest.env_for('/path?q=...'))`.
- Booting Rails needs its database configuration; use a SQLite file the probe creates only if
  the app supports that adapter, and say so.
- A target that calls `exit` raises `SystemExit`: `rescue SystemExit` around the call so the
  line still prints. Set `$stdout.sync = true` so ordering is preserved.

## The HARNESS_PROBE line

In Ruby only `nil` and `false` are falsy: `0` and `""` are **true**. Convert explicitly:

```ruby
require 'json'
puts 'HARNESS_PROBE ' + JSON.generate('target_reached' => t == true, 'oracle_valid' => o == true,
  'positive_control' => p == true, 'negative_control' => n == true, 'vulnerability_observed' => v == true)
```

## Common failure modes

- `Bundler::GemNotFound` or a `BUNDLED WITH` version mismatch: a dependency limitation.
- Autoloading (Zeitwerk) not loading a constant outside the booted app: boot the app first.
- RSpec/Minitest print a summary after your output: run a plain script for the evidence-bearing
  run, not the test runner.
- Native-extension gems need `gcc` and headers at install time; their absence is a limitation.

## When the toolchain is absent

Run `command -v ruby` first. If it prints nothing, Ruby is not installed in this image: do not
download Ruby or gems, and do not port the code to Python (a port is a stand-in, never the
target). Return `inconclusive`, name `ruby: not found` as the limitation in the verdict
summary, and record what reading established (sink line, guard line, the oracle you would
run). A `.ruby-version` file or CI config naming Ruby is not execution evidence.

## Completion criteria

- You can name the framework, the route or method reaching the sink, how the probe supplied
  the request, and either the probe you ran or the exact missing tool.
