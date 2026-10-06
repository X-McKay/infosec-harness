---
name: cwe-489-active-debug-code
description: Recognize debug modes, debug endpoints and leftover test hooks reachable in production, and
  define a loopback oracle. Use this when the finding is CWE-489 or CWE-11 or names debug code.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-489: Active debug code

## Use this skill when

- The finding is classified CWE-489 or CWE-11 (ASP.NET debug binary), or names a debug
  mode, debug route, test backdoor or development-only handler left enabled.
- A framework debug flag (`app.run(debug=True)`, `DEBUG = True`, `devtool`, `-Xdebug`) or a
  route such as `/debug`, `/__test__`, `/console` is enabled by default or by a value the
  deployment does not control.

## Do not use this skill when

- Production code formats internals into an error regardless of mode — use
  `cwe-200-information-exposure`.
- The debug endpoint evaluates caller-supplied code — use `cwe-94-code-injection` for the
  evaluation and cite this skill only for how the endpoint became reachable.
- The issue is a general insecure default with no debug feature — use
  `cwe-16-security-misconfiguration`.

## When another skill also applies

- `cwe-200-information-exposure` also fires when the debug mode leaks tracebacks. **This
  skill wins** when switching the debug feature off is the fix; that skill wins when the leak
  survives with debug off.
- `cwe-94-code-injection` **wins** for an interactive debugger console: its oracle observes
  evaluation directly, which is stronger evidence than reaching the console.

## Procedure

**Sink.** A debug-only capability reachable by an untrusted caller: a route registered
unconditionally, a debug flag that turns on verbose errors or an interactive console, a hidden
parameter (`?debug=1`, `X-Debug` header) that bypasses checks or dumps state.

**Guard.** Registration conditioned on an environment value the operator sets; a production
configuration that defaults to off; authentication on the debug route; binding the debug
server to loopback only.

**Neutralized when.** In the configuration the code ships with (no developer environment
variables set), the debug capability is not registered or not reachable without credentials
the attacker lacks. Cite the line that sets the default.

**Source.** The request path, query parameter or header that selects the debug behaviour,
and the configuration default that leaves it on.

## Oracle

Condition: **with the shipped default configuration, an unauthenticated request reaches a
debug-only behaviour.** Start the target's real application object on `127.0.0.1` with an
ephemeral port, without setting developer environment variables, and request the debug
route or parameter with the standard-library client. Observe a debug-only marker: a
response from the debug route, a traceback page, a state dump, or a check skipped.

- `target_reached`: the real application handled the request, including a 404 or 401.
- `vulnerability_observed`: the debug-only marker appears in the response to the
  unauthenticated request under the default configuration.
- `positive_control`: the same request with the debug feature explicitly enabled through the
  target's own documented switch produces the marker, proving the check detects it.
- `negative_control`: a request to an ordinary route returns normal output and no marker.

Do not invoke an interactive debugger's evaluation features; reaching it is the observation.

## Language notes

- **Python**: Flask `debug=True` (Werkzeug console), Django `DEBUG = True`, `pdb.set_trace()`
  in a request path, `http.server` handlers with a `/debug` branch.
- **JavaScript**: Express routes behind `if (process.env.NODE_ENV !== 'production')` (the
  default is unset, so the branch is on), `--inspect` in start scripts, `app.use(errorhandler())`.
- **Java**: Spring Boot Actuator endpoints exposed with `management.endpoints.web.exposure.include=*`,
  `-agentlib:jdwp` in launch scripts, servlet test hooks in `web.xml`.
- **Perl**: `CGI::Carp qw(fatalsToBrowser)`, `$DEBUG = 1` package defaults, Mojolicious
  `development` mode as the default.

## Pitfalls

- A debug flag in a test configuration or a `make dev` target is not production exposure;
  find the production entry point first (see `investigate`).
- Setting the flag yourself and then observing it proves the positive control only.
- `--inspect` or JDWP bound to loopback needs local access; scope the claim accordingly.

## Verdict guidance

- `potentially_exploitable`: the shipped default enables the debug capability and the oracle
  fired through the real application.
- `likely_not_exploitable`: the cited default disables it or the route requires credentials,
  with both controls passing.
- `inconclusive`: reachability depends on deployment configuration not present in the
  repository; name the setting.
