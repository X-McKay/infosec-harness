---
name: lang-php
description: 'Conventions for PHP repositories: Composer autoload, front controllers, superglobals and
  CLI probes. Use this when the repository is primarily PHP; the workspace image has no PHP runtime by default.'
metadata:
  owner: appsec
  version: 1.0.0
---

# PHP repositories

## First: check the toolchain

The workspace image does **not** include PHP or Composer. Before anything else run
`command -v php` and, if it prints a path, `php -v` and `php -m` (loaded extensions). If PHP
is absent, read the code to locate the sink and guard, then follow "When the toolchain is absent".

## Use this skill when

- The repository has `composer.json` or `.php` files hold the finding's sink.

## Do not use this skill when

- The PHP is a vendored library under `vendor/` that no production entry point calls.
- You are planning installs — use `environment`. This skill grants no permissions.

## Recognize the project

- **Manifests:** `composer.json` (`autoload` PSR-4 map, `require`, `scripts`), `composer.lock`,
  `vendor/autoload.php` and `vendor/composer/installed.json` when dependencies are committed.
- **Frameworks:** Laravel (`artisan`, `routes/web.php`, `app/Http/Controllers`), Symfony
  (`bin/console`, `config/routes.yaml`, `#[Route]`), WordPress (`wp-config.php`, `add_action`
  hooks, `wp_ajax_*`), plain scripts reached through `public/index.php` or per-file URLs.
- **Entry points:** controller actions, any file reading `$_GET`/`$_POST`/`$_REQUEST`/
  `$_COOKIE`/`$_FILES`/`$_SERVER`, `php://input`, CLI scripts using `$argv`.
- **Sinks to note:** `system`/`exec`/`shell_exec`/`passthru`/backticks/`proc_open`,
  `mysqli_query`/`PDO::query` with interpolation, `include`/`require` with a variable path,
  `unserialize`, `eval`/`assert` with strings/`preg_replace` with `/e`, `echo` without
  `htmlspecialchars`, `file_get_contents($url)`, loose `==` comparisons on secrets.

## Inspect dependencies offline

Read `composer.lock` for exact versions; `vendor/composer/installed.json` lists what is
actually present. Composer `scripts` and plugins execute repository code. Composer is not in
the image: never fetch `composer.phar`, and never run Composer's dependency installer against a
network index from a skill's suggestion. Without a committed `vendor/autoload.php`, require the
target's own files directly when its dependencies allow it; otherwise report the gap.

## Compile and run a probe

PHP needs no build. Write `.harness-probe/probe.php` and run it inside `run_probe`:

```bash
php -d display_errors=stderr -d error_reporting=E_ALL .harness-probe/probe.php
```

- Load code with `require __DIR__ . '/../vendor/autoload.php';` or the target file itself.
- For a script that reads superglobals, assign `$_GET`/`$_POST`/`$_SERVER` in the probe before
  `include`-ing it, wrapped in `ob_start()`/`ob_get_clean()` so its output stays captured.
- A target that calls `exit`/`die` ends the probe: emit the line from a
  `register_shutdown_function` callback registered before the target call.
- For a full HTTP path, `php -S 127.0.0.1:<port> -t public` in the background is loopback
  only; request it with `file_get_contents('http://127.0.0.1:<port>/...')` and stop it after.

## The HARNESS_PROBE line

Cast every value: `json_encode` turns `1`/`0` and `null` into numbers and `null`.

```php
echo 'HARNESS_PROBE ' . json_encode(['target_reached' => (bool) $t, 'oracle_valid' => (bool) $o,
    'positive_control' => (bool) $p, 'negative_control' => (bool) $n,
    'vulnerability_observed' => (bool) $v]) . PHP_EOL;
```

## Common failure modes

- A missing extension (`pdo_sqlite`, `mbstring`, `xml`): check `php -m`; a limitation, not a guard.
- Notices or warnings printed to stdout after your line: send errors to stderr as above.
- Version-dependent behaviour (PHP 8 changed `"abc" == 0` and many warnings): record `php -v`.
- `open_basedir`/`disable_functions` from a repository `php.ini` or `.user.ini`: note whether
  the deployment applies it before treating it as a guard.

## When the toolchain is absent

Run `command -v php` first. If it prints nothing, PHP is not installed in this image: do not
download a PHP binary or Composer, and do not port the code to Python or JavaScript (a port is
a stand-in, never the target). Return `inconclusive`, name `php: not found` as the limitation
in the verdict summary, and record what reading established (sink line, guard line, the oracle
you would run). A `composer.json` `php` constraint or a Dockerfile naming PHP is not
execution evidence.

## Completion criteria

- You can name the framework, the route or file that reaches the sink, how the probe supplied
  the request, and either the probe you ran or the exact missing tool.
