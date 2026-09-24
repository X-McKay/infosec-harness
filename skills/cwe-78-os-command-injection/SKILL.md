---
name: cwe-78-os-command-injection
description: "Recognize OS command injection sources, sinks, and sanitizers, and define a canary-file oracle."
---

# CWE-78: OS command injection

**Sink.** Passing a string to a shell: `os.system`, `subprocess.*(..., shell=True)`,
`Runtime.exec("sh -c ...")`, `child_process.exec`, backticks / `system()` in Perl, where the
command string includes untrusted input.

**Source.** Untrusted values reaching the command string.

**Neutralized when.** The program uses the argument-vector form with no shell
(`subprocess.run([...], shell=False)`, `ProcessBuilder(list)`, `execFile`) and the untrusted
value is a single argument, or the value is strictly allowlisted.

## Oracle

Use a **canary_file** oracle (see probe-oracle-protocol). Construct the input so that, *if*
the shell interprets it, a benign marker command runs that creates the sandbox file
`/tmp/harness_canary_<nonce>` (for example, appending a shell separator followed by a `touch`
of that path). The marker command does nothing but create that file inside the sandbox — no
network, no data access, no destructive action.

- Print the precondition marker just before calling the sink.
- The runner reports the oracle as fired iff the canary file exists afterward. If the program
  used the no-shell argument-vector form, the separators are inert and the file is absent — a
  valid negative.

Keep the injected fragment minimal and inert; its only purpose is to prove the shell evaluated
attacker-controlled text.
