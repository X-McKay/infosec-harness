"""Language-aware callable inspection for repository source files."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from pydantic_ai import ModelRetry, RunContext

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.repo_tools import (
    MAX_FILE_BYTES,
    _read_capped,
    _resolve,
    clip_bytes,
    list_files,
)

MAX_SYMBOLS = 80
MAX_SYMBOL_SOURCE_LINES = 4000
MAX_SYMBOL_FIELD = 300
MAX_DESCRIBE_BYTES = 100_000


@dataclass(frozen=True)
class _Symbol:
    """One callable a file defines, plus how a test reaches it."""

    name: str
    kind: str  # function | method | class | constructor | sub | exported binding
    params: str | None  # None when the declaration form does not reveal them
    line: int
    export: str  # named | default | module-level | package sub | none | unknown
    reach: str  # the literal import/require/instantiation a test would write
    notes: tuple[str, ...] = ()


_LANG_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    # TypeScript goes through the JavaScript scanner. It has to: `detect_stack` reports a `.ts`
    # repository as `typescript`, and with these four suffixes absent this tool refused every file
    # in one — so the single tool that exists to stop the named-vs-default false negative was
    # unavailable on exactly the repositories most likely to have a deep export chain. The
    # declaration forms the scanner matches (`export function`, `export {}`, `module.exports`) are
    # spelled identically in TypeScript; only the type annotations differ, and they sit inside the
    # parameter list this scan already reports verbatim.
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mts": "javascript",
    ".cts": "javascript",
    ".java": "java",
    ".pl": "perl",
    ".pm": "perl",
    ".t": "perl",
}

# What is certain and what is guessed, stated per language rather than implied.
_CERTAINTY = {
    "python": (
        "parsed with Python's `ast`: names, kinds and parameter lists are CERTAIN. The dotted "
        "module path is DERIVED from the file's path below the snapshot root and is only valid "
        "if that root is on sys.path (pytest rootdir)."
    ),
    "javascript": (
        "heuristic text scan, no JS parser: names and the export form are CERTAIN (matched "
        "literally in the source); parameter lists are INFERRED from the declaration text and "
        "class membership is INFERRED from brace depth. The module specifier is relative to the "
        "snapshot root - rewrite it relative to your test file."
    ),
    "java": (
        "heuristic text scan, no Java parser: the package, the type names and each signature "
        "printed below are CERTAIN (matched literally in the source). Which type OWNS a member is "
        "INFERRED from declaration order, and completeness is NOT guaranteed - a member this scan "
        "missed simply does not appear, so confirm with read_file before concluding one is absent."
    ),
    "perl": (
        "heuristic text scan, no Perl parser: package names, `sub` names and the @EXPORT / "
        "@EXPORT_OK lists are CERTAIN (matched literally); parameter names are INFERRED from the "
        "first `my (...) = @_;` in the body, and method-vs-function is INFERRED from whether that "
        "unpacks $self."
    ),
}


def _clip(text: str) -> str:
    return text if len(text) <= MAX_SYMBOL_FIELD else text[:MAX_SYMBOL_FIELD] + "...(clipped)"


def _py_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    a = node.args
    positional = [*a.posonlyargs, *a.args]
    first_default = len(positional) - len(a.defaults)
    parts = [arg.arg + ("=..." if i >= first_default else "") for i, arg in enumerate(positional)]
    if a.posonlyargs:
        parts.insert(len(a.posonlyargs), "/")
    if a.vararg:
        parts.append("*" + a.vararg.arg)
    elif a.kwonlyargs:
        parts.append("*")
    for arg, default in zip(a.kwonlyargs, a.kw_defaults, strict=False):
        parts.append(arg.arg + ("=..." if default is not None else ""))
    if a.kwarg:
        parts.append("**" + a.kwarg.arg)
    return "(" + ", ".join(parts) + ")"


def _py_call_hint(node: ast.FunctionDef | ast.AsyncFunctionDef, drop_self: bool = False) -> str:
    """A call whose shape is valid: positionals bare, keyword-only as `name=...`."""
    a = node.args
    positional = [arg.arg for arg in (*a.posonlyargs, *a.args)]
    if drop_self and positional and positional[0] in ("self", "cls"):
        positional = positional[1:]
    parts = list(positional)
    if a.vararg:
        parts.append("*" + a.vararg.arg)
    parts += [f"{arg.arg}=..." for arg in a.kwonlyargs]
    if a.kwarg:
        parts.append("**" + a.kwarg.arg)
    return ", ".join(parts)


def _py_signature_without_self(node: ast.FunctionDef) -> str:
    params = _py_params(node)
    inner = params[1:-1]
    parts = [p.strip() for p in inner.split(",")]
    if parts and parts[0] in ("self", "cls"):
        parts = parts[1:]
        if parts and parts[0] == "/":
            parts = parts[1:]
    return "(" + ", ".join(parts) + ")"


def _python_symbols(text: str, rel: Path) -> tuple[list[_Symbol], list[str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        return [], [f"`ast` refused this file ({e.msg} at line {e.lineno}); nothing is reported "
                    "rather than guessing. Read it with read_file instead."]
    parts = [*rel.parts[:-1], rel.stem]
    if parts and parts[-1] == "__init__":
        parts.pop()
    module = ".".join(parts)
    header: list[str] = []
    if not all(p.isidentifier() for p in parts):
        header.append(f"WARNING: path segments of {rel.as_posix()!r} are not all valid Python "
                      f"identifiers, so the dotted path {module!r} is a guess - the file may only "
                      "be importable via importlib or a conftest sys.path insert.")
    out: list[_Symbol] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            params = _py_params(node)
            out.append(_Symbol(
                name=node.name, kind="function", params=params, line=node.lineno,
                export="module-level",
                reach=f"from {module} import {node.name}  ->  {node.name}({_py_call_hint(node)})",
                notes=("no instance needed",),
            ))
        elif isinstance(node, ast.ClassDef):
            init = next((m for m in node.body
                         if isinstance(m, ast.FunctionDef) and m.name == "__init__"), None)
            ctor_sig = _py_signature_without_self(init) if init else "()"
            ctor_call = f"({_py_call_hint(init, drop_self=True)})" if init else "()"
            out.append(_Symbol(
                name=node.name, kind="class", params=ctor_sig, line=node.lineno,
                export="module-level",
                reach=f"from {module} import {node.name}  ->  {node.name}{ctor_call}",
                notes=("construct an instance before calling its methods; the params above are "
                       "__init__'s" if init else
                       "no __init__ of its own, so construct it with no arguments",),
            ))
            for member in node.body:
                if not isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                if member.name == "__init__":
                    continue  # already reported as the class's constructor signature
                decorators = {d.id for d in member.decorator_list if isinstance(d, ast.Name)}
                bound = "staticmethod" not in decorators and "classmethod" not in decorators
                receiver = f"{node.name}{ctor_call}" if bound else node.name
                out.append(_Symbol(
                    name=f"{node.name}.{member.name}", kind="method",
                    params=_py_params(member), line=member.lineno,
                    export="module-level (via its class)",
                    reach=(f"from {module} import {node.name}  ->  {receiver}.{member.name}"
                           f"({_py_call_hint(member, drop_self=True)})"),
                    notes=(("needs an instance",) if bound
                           else ("callable on the class, no instance needed",)),
                ))
    return out, header


_JS_FUNC = re.compile(
    r"^(?P<indent>\s*)(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s*\*?\s*"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)")
_JS_VAR_FUNC = re.compile(
    r"^(?P<indent>\s*)(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:async\s+)?(?:function\s*\*?\s*\((?P<params>[^)]*)\)"
    r"|\((?P<aparams>[^)]*)\)\s*=>|(?P<single>[A-Za-z_$][\w$]*)\s*=>)")
_JS_CLASS = re.compile(
    r"^(?P<indent>\s*)(?:export\s+(?:default\s+)?)?class\s+(?P<name>[A-Za-z_$][\w$]*)")
_JS_METHOD = re.compile(
    r"^\s+(?P<static>static\s+)?(?:async\s+)?(?:get\s+|set\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*"
    r"\((?P<params>[^)]*)\)\s*\{")
_JS_NOT_A_METHOD = {"if", "for", "while", "switch", "catch", "function", "return", "do", "else"}


_TS_SUFFIXES = (".ts", ".tsx", ".mts", ".cts")


def _js_specifier(rel: Path, esm: bool) -> str:
    """The specifier a test writes for this file, relative to the snapshot root.

    An ESM specifier KEEPS its `.js` extension. Node's ESM resolver does no extension guessing,
    so an extensionless `import { x } from "../src/render"` dies with ERR_MODULE_NOT_FOUND under
    `node --test` and under plain node -- measured -- while vitest and jest's vm-modules mode
    forgive it. Printing the form that works everywhere is strictly better than printing the one
    that works under two runners out of four.

    TypeScript is the opposite: the extension comes off, because `./src/render.ts` is what
    ts-jest and tsc's own resolver reject.
    """
    if rel.suffix in _TS_SUFFIXES:
        return "./" + rel.with_suffix("").as_posix()
    if esm:
        return "./" + rel.as_posix()
    stem = rel.with_suffix("") if rel.suffix in (".js", ".jsx") else rel
    return "./" + stem.as_posix()


def _js_exports(text: str) -> tuple[dict[str, str], str | None, str]:
    """Return (exported name -> local name, default export local name, module system)."""
    named: dict[str, str] = {}
    default: str | None = None
    system = "unknown"
    if re.search(r"\b(?:module\.exports|exports\.)", text):
        system = "CommonJS (module.exports / exports.x)"
    if re.search(r"^\s*export\s", text, re.M):
        system = "ES modules (export)" if system == "unknown" else "mixed CommonJS and ES modules"

    block = re.search(r"module\.exports\s*=\s*\{([^{}]*)\}", text)
    if block:
        for entry in block.group(1).split(","):
            m = re.match(r"\s*(?P<key>[A-Za-z_$][\w$]*)\s*(?::\s*(?P<val>[A-Za-z_$][\w$]*))?\s*$",
                         entry)
            if m:
                named[m.group("key")] = m.group("val") or m.group("key")
    else:
        whole = re.search(r"module\.exports\s*=\s*(?!\{)(?:async\s+)?"
                          r"(?:function\s*\*?\s*(?P<fn>[A-Za-z_$][\w$]*)?|(?P<id>[A-Za-z_$][\w$]*))",
                          text)
        if whole:
            default = whole.group("fn") or whole.group("id")
    for m in re.finditer(r"(?:module\.)?exports\.(?P<key>[A-Za-z_$][\w$]*)\s*=\s*"
                         r"(?P<val>[A-Za-z_$][\w$]*)?", text):
        named[m.group("key")] = m.group("val") or m.group("key")
    for m in re.finditer(r"^\s*export\s+(?:async\s+)?(?:function\s*\*?\s*|class\s+"
                         r"|(?:const|let|var)\s+)(?P<name>[A-Za-z_$][\w$]*)", text, re.M):
        named[m.group("name")] = m.group("name")
    for m in re.finditer(r"^\s*export\s*\{([^}]*)\}", text, re.M):
        for entry in m.group(1).split(","):
            parts = re.findall(r"[A-Za-z_$][\w$]*", entry)
            if len(parts) == 1:
                named[parts[0]] = parts[0]
            elif len(parts) >= 3 and parts[1] == "as":  # `local as exported`
                named[parts[2]] = parts[0]
    esm_default = re.search(r"^\s*export\s+default\s+(?:async\s+)?"
                            r"(?:function\s*\*?\s*(?P<fn>[A-Za-z_$][\w$]*)?"
                            r"|class\s+(?P<cls>[A-Za-z_$][\w$]*)|(?P<id>[A-Za-z_$][\w$]*))",
                            text, re.M)
    if esm_default:
        default = esm_default.group("fn") or esm_default.group("cls") or esm_default.group("id")
    return named, default, system


def _js_reach(local: str, named: dict[str, str], default: str | None, spec: str,
              esm: bool) -> tuple[str, str, tuple[str, ...]]:
    exported = next((k for k, v in named.items() if v == local), None)
    if exported is not None:
        if esm:
            binding = exported if exported == local else f"{exported} as {local}"
            return "named", f'import {{ {binding} }} from "{spec}";', (
                "NAMED export - the braces are required; `import x from` would bind the module "
                "namespace, not this symbol.",)
        binding = exported if exported == local else f"{exported}: {local}"
        return "named", f'const {{ {binding} }} = require("{spec}");', (
            "NAMED export - destructure it; `const x = require(...)` binds the module OBJECT, "
            "not this symbol, and calling it throws TypeError.",)
    if default == local:
        if esm:
            return "default", f'import {local} from "{spec}";', (
                "DEFAULT export - no braces.",)
        return "default", f'const {local} = require("{spec}");', (
            "sole `module.exports = ...` value, so require() returns it directly - do NOT "
            "destructure.",)
    return "none", (
        f'not exported from {spec} - require() cannot reach it. Drive it through an exported '
        f'caller in this file, or read the file that re-exports it.'), ()


@dataclass
class _ClassScope:
    """Which class a JavaScript line sits inside, INFERRED from brace depth (no parser).

    A class is open from its declaration until the brace depth falls back to where it stood
    when the class was declared.
    """

    depth: int = 0
    _open: list[tuple[str, int]] = field(default_factory=list)  # (class name, depth at opening)

    @property
    def owner(self) -> str | None:
        return self._open[-1][0] if self._open else None

    def open(self, name: str) -> None:
        self._open.append((name, self.depth))

    def advance(self, line: str) -> None:
        self.depth += line.count("{") - line.count("}")
        while self._open and self.depth <= self._open[-1][1]:
            self._open.pop()


def _javascript_symbols(text: str, rel: Path) -> tuple[list[_Symbol], list[str]]:
    named, default, system = _js_exports(text)
    esm = system.startswith("ES modules")
    spec = _js_specifier(rel, esm)
    header = [f"module system: {system}"]
    if rel.suffix in _TS_SUFFIXES:
        header.append(
            "TypeScript source: the specifier below is extensionless on purpose, and the probe "
            "needs a runner that compiles TS. A bare `npx jest` does not — its default transform "
            "has no TypeScript plugin and the suite fails to parse before any test runs. vitest "
            "and `npx tsx --test` compile it with no configuration; jest needs ts-jest AND the "
            "type declarations for the test globals (@types/jest), because ts-jest type-checks "
            "the probe and stops on `TS2582: Cannot find name 'test'`.")
    if esm and rel.suffix not in _TS_SUFFIXES:
        header.append(
            "ES module: keep the file extension in the specifier exactly as printed. Node's ESM "
            "resolver does no extension guessing, so dropping it fails with ERR_MODULE_NOT_FOUND "
            "under `node --test` and plain node.")
    if re.search(r"module\.exports\s*=\s*\{[^}]*[{]", text):
        header.append("WARNING: `module.exports = { ... }` contains a nested object literal; this "
                      "scan does not descend into it, so the export list below may be incomplete.")
    out: list[_Symbol] = []
    scope = _ClassScope()
    for lineno, line in enumerate(text.splitlines(), start=1):
        cls = _JS_CLASS.match(line)
        method = None if cls else _JS_METHOD.match(line)
        func = _JS_FUNC.match(line)
        var = None if func else _JS_VAR_FUNC.match(line)
        if cls:
            name = cls.group("name")
            export, reach, notes = _js_reach(name, named, default, spec, esm)
            out.append(_Symbol(name=name, kind="class", params=None, line=lineno, export=export,
                               reach=reach,
                               notes=(*notes, "construct an instance before calling its methods")))
            scope.open(name)
        elif func or var:
            m = func or var
            assert m is not None
            name = m.group("name")
            params = m.group("params")
            if params is None and var is not None:
                params = var.group("aparams")
                if params is None and var.group("single"):
                    params = var.group("single")
            owner = scope.owner if m.group("indent") else None
            export, reach, notes = _js_reach(owner or name, named, default, spec, esm)
            out.append(_Symbol(
                name=f"{owner}.{name}" if owner else name,
                kind="method" if owner else "function",
                params=f"({params or ''})", line=lineno, export=export,
                reach=reach if not owner else f"{reach}  ->  new {owner}(...).{name}(...)",
                notes=notes if not owner else (*notes, "needs an instance"),
            ))
        elif method and method.group("name") not in _JS_NOT_A_METHOD and scope.owner:
            owner = scope.owner
            name, params = method.group("name"), method.group("params")
            export, reach, notes = _js_reach(owner, named, default, spec, esm)
            if name == "constructor":
                kind, call, hint = "constructor", f"new {owner}({params})", "invoked by `new`"
            elif method.group("static"):
                kind, call, hint = "method", f"{owner}.{name}({params})", "static, no instance needed"
            else:
                kind = "method"
                call, hint = f"new {owner}(...).{name}({params})", f"needs an instance of {owner}"
            out.append(_Symbol(
                name=f"{owner}.{name}", kind=kind, params=f"({params})",
                line=lineno, export=export, reach=f"{reach}  ->  {call}",
                notes=(*notes, hint),
            ))
        scope.advance(line)
    for exported, local in sorted(named.items()):
        if not any(s.name == local or s.name.endswith(f".{local}") for s in out):
            out.append(_Symbol(
                name=exported, kind="exported binding", params=None, line=0, export="named",
                reach=(f'const {{ {exported} }} = require("{spec}");' if not esm
                       else f'import {{ {exported} }} from "{spec}";'),
                notes=(f"exported as a NAMED binding but no `{local}` declaration was matched in "
                       "this file - it is re-exported from elsewhere or declared in a form this "
                       "scan does not recognise. Confirm with search_code.",),
            ))
    return out, header


_JAVA_TYPE = re.compile(
    r"^\s*(?:public\s+|protected\s+|private\s+|abstract\s+|final\s+|static\s+|sealed\s+"
    r"|non-sealed\s+)*(?P<kw>class|interface|enum|record)\s+(?P<name>[A-Za-z_$][\w$]*)", re.M)
_JAVA_MEMBER = re.compile(
    r"^\s+(?P<mods>(?:public|protected|private|static|final|synchronized|abstract|native|"
    r"default)\s+(?:\w+\s+)*?)(?:(?P<ret>[\w$<>\[\],.?\s]+?)\s+)?"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)\s*(?:throws [\w\s,.]+)?\{", re.M)


def _java_symbols(text: str, rel: Path) -> tuple[list[_Symbol], list[str]]:
    pkg_match = re.search(r"^\s*package\s+([\w.]+)\s*;", text, re.M)
    pkg = pkg_match.group(1) if pkg_match else ""
    header = [f"package: {pkg or '(default package - no `package` declaration found)'}"]
    types = [(m.group("name"), m.group("kw"), text[:m.start()].count("\n") + 1)
             for m in _JAVA_TYPE.finditer(text)]
    primary = types[0][0] if types else rel.stem
    if primary != rel.stem:
        header.append(f"WARNING: the first declared type is {primary!r} but the file is "
                      f"{rel.name!r}; javac requires the public type to match the file name, so "
                      "one of the two is not what it appears.")
    if pkg and pkg.replace(".", "/") not in rel.as_posix():
        header.append(f"WARNING: package {pkg!r} does not match the file's directory "
                      f"{rel.parent.as_posix()!r}; the build may not find this class.")
    out: list[_Symbol] = []
    type_names = {name for name, _, _ in types}
    for name, kw, lineno in types:
        fqcn = f"{pkg}.{name}" if pkg else name
        out.append(_Symbol(
            name=name, kind=kw, params=None, line=lineno, export=f"public type {fqcn}",
            reach=(f"import {fqcn};  ->  new {name}(...)" if kw in ("class", "record")
                   else f"import {fqcn};"),
            notes=(("a test in package " + pkg + " needs no import",) if pkg else ()),
        ))
    for m in _JAVA_MEMBER.finditer(text):
        name, mods = m.group("name"), m.group("mods")
        if name in ("if", "for", "while", "switch", "catch", "synchronized", "new", "return"):
            continue
        lineno = text[:m.start()].count("\n") + 1
        static = "static" in mods
        owner = next((t for t, _, tl in types if tl <= lineno), primary)
        fqcn = f"{pkg}.{owner}" if pkg else owner
        if name in type_names:  # a constructor
            out.append(_Symbol(
                name=f"{owner}({m.group('params')})", kind="constructor",
                params=f"({m.group('params')})", line=lineno, export=f"public type {fqcn}",
                reach=f"import {fqcn};  ->  new {owner}({m.group('params')})", notes=()))
            continue
        out.append(_Symbol(
            name=f"{owner}.{name}", kind="method", params=f"({m.group('params')})", line=lineno,
            export=("public static" if static and "public" in mods else
                    "public" if "public" in mods else "not public - " + mods.strip()),
            reach=(f"import {fqcn};  ->  {owner}.{name}(...)" if static
                   else f"import {fqcn};  ->  new {owner}(...).{name}(...)"),
            notes=(("static, no instance needed",) if static else ("needs an instance",))
            + (() if "public" in mods
               else ("not public: only a test in the same package can call it",)),
        ))
    return out, header


_PERL_SUB = re.compile(r"^\s*sub\s+(?P<name>[A-Za-z_][\w]*)\b")
_PERL_ARGS = re.compile(r"\bmy\s*\((?P<params>[^)]*)\)\s*=\s*@_")
_PERL_SHIFT = re.compile(r"\bmy\s+(?P<var>\$[A-Za-z_]\w*)\s*=\s*shift")


def _perl_symbols(text: str, rel: Path) -> tuple[list[_Symbol], list[str]]:
    lines = text.splitlines()
    packages = [(m.group(1), text[:m.start()].count("\n") + 1)
                for m in re.finditer(r"^\s*package\s+([\w:]+)\s*;", text, re.M)]
    default_exports: set[str] = set()
    optional_exports: set[str] = set()
    for m in re.finditer(r"^\s*(?:our\s+)?@EXPORT(?P<ok>_OK)?\s*=\s*qw\(([^)]*)\)", text, re.M):
        (optional_exports if m.group("ok") else default_exports).update(m.group(2).split())
    pkg_name = packages[0][0] if packages else rel.stem
    header = [f"package: {pkg_name}" + (f" (+{len(packages) - 1} more in this file)"
                                        if len(packages) > 1 else "")]
    if re.search(r"^\s*(?:use|require)\s+(?:parent\s+.*)?Exporter", text, re.M):
        header.append("uses Exporter: @EXPORT = "
                      f"{sorted(default_exports) or '(none)'}, @EXPORT_OK = "
                      f"{sorted(optional_exports) or '(none)'}")
    else:
        header.append("no Exporter found: nothing is importable into a test's namespace, so call "
                      "subs fully qualified.")
    expected = pkg_name.replace("::", "/") + ".pm"
    if rel.suffix == ".pm" and not rel.as_posix().endswith(expected):
        header.append(f"WARNING: package {pkg_name!r} implies the file {expected!r} but this file "
                      f"is {rel.as_posix()!r}; `use {pkg_name}` will not find it without the right "
                      "`use lib`.")
    out: list[_Symbol] = []
    for i, line in enumerate(lines):
        m = _PERL_SUB.match(line)
        if not m:
            continue
        lineno = i + 1
        name = m.group("name")
        owner = next((p for p, pl in reversed(packages) if pl <= lineno), pkg_name)
        params: str | None = None
        is_method = False
        # The body may start on the `sub` line itself, so include it minus the declaration.
        window = "\n".join([line[line.index("{") + 1:] if "{" in line else "",
                            *lines[i + 1 : i + 5]])
        args, shift = _PERL_ARGS.search(window), _PERL_SHIFT.search(window)
        if args and (shift is None or args.start() <= shift.start()):
            names = [p.strip() for p in args.group("params").split(",") if p.strip()]
            is_method = bool(names) and names[0] in ("$self", "$class")
            params = "(" + ", ".join(names) + ")"
        elif shift:
            is_method = shift.group("var") in ("$self", "$class")
            params = f"({shift.group('var')}, ...)"
        use = f"use lib 'lib'; use {owner};"
        if is_method:
            # A method is reached through the class or an instance, so @EXPORT is irrelevant to it.
            class_method = (params or "").startswith("($class")
            export = "method (not reached by import)"
            reach = (f"{use}  ->  {owner}->{name}(...)" if class_method
                     else f"{use}  ->  my $obj = {owner}->new(...); $obj->{name}(...)")
            notes: tuple[str, ...] = (
                f"unpacks {'$class' if class_method else '$self'}, so it is a method - invoke it "
                "with `->`, not as a plain sub",)
        elif name in default_exports:
            export = "@EXPORT (imported by default)"
            reach = f"{use}  ->  {name}(...)"
            notes = ("imported into the caller's namespace unqualified",)
        elif name in optional_exports:
            export = "@EXPORT_OK (must be requested)"
            reach = f"use lib 'lib'; use {owner} qw({name});  ->  {name}(...)"
            notes = (f"you MUST list it in the `use` - a bare `use {owner};` does not import it",)
        else:
            export = "not exported"
            reach = f"{use}  ->  {owner}::{name}(...)"
            notes = ("not exported: call it FULLY QUALIFIED as "
                     f"{owner}::{name}; an unqualified call will not resolve",)
        out.append(_Symbol(name=f"{owner}::{name}", kind="method" if is_method else "sub",
                           params=params, line=lineno, export=export, reach=reach, notes=notes))
    return out, header


_EXTRACTORS = {
    "python": _python_symbols,
    "javascript": _javascript_symbols,
    "java": _java_symbols,
    "perl": _perl_symbols,
}


# A `ModelRetry` that only says what is wrong costs the run three calls and then aborts the
# whole finding with "exceeded max retries count of 2" — measured on java-sqli-vulnerable, where
# the model called this tool with something that is not a repo-relative file path. So every
# retry below names the path to call INSTEAD, the same contract the deterministic validators in
# agents/validators.py hold themselves to. The candidate search goes through `list_files`, which
# is already confined to the snapshot root: nothing here walks or stats outside it.

_SUPPORTED_EXTS = ", ".join(sorted(_LANG_BY_SUFFIX))
_MAX_NAMED_CANDIDATES = 8


def _supported_matches(ctx: RunContext[AgentDeps], directory: str, pattern: str) -> list[str]:
    """Repo-relative paths under `directory` matching `pattern` that this tool can parse."""
    listing = list_files(ctx, directory, pattern)
    return [line for line in listing.splitlines()
            if line and not line.startswith(("(no matches)", "... truncated"))
            and Path(line).suffix.lower() in _LANG_BY_SUFFIX]


def _likely_stems(path: str) -> list[str]:
    """File stems the caller may have meant, best guess first.

    `com.example.UserDao` -> [`UserDao`, `com.example`], `com/example/UserDao.java` ->
    [`UserDao`], `UserDao.class` -> [`class`, `UserDao`]. A fully-qualified class name and a
    package path both end in the component that names the file, which is what makes the
    corrected path findable; a stem that matches nothing just falls through to the next.
    """
    token = path.replace("\\", "/").rstrip("/").split("/")[-1]
    parts = [p for p in token.split(".") if p]
    out: list[str] = []
    if len(parts) > 1 and f".{parts[-1].lower()}" in _LANG_BY_SUFFIX:
        out.append(parts[-2])  # a real extension: the stem is what precedes it
    elif parts:
        out.append(parts[-1])  # `com.example.UserDao`: the type name is the last segment
    stem = Path(token).stem
    if stem and stem not in out:
        out.append(stem)
    return out


def _name_them(candidates: list[str]) -> str:
    shown = candidates[:_MAX_NAMED_CANDIDATES]
    more = ("" if len(candidates) <= _MAX_NAMED_CANDIDATES
            else f" (and {len(candidates) - _MAX_NAMED_CANDIDATES} more)")
    return ", ".join(repr(c) for c in shown) + more


def _not_a_file_retry(ctx: RunContext[AgentDeps], path: str, target: Path) -> ModelRetry:
    """The retry for a `path` that resolved inside the repo but is not a readable source file."""
    root = Path(ctx.deps.repo_path).resolve()
    if target.is_dir():
        rel_dir = target.relative_to(root).as_posix() or "."
        inside = _supported_matches(ctx, rel_dir, "*")
        if inside:
            return ModelRetry(
                f"{path!r} is a directory, and describe_callables takes one source file. Call it "
                f"again with one of the files it contains: {_name_them(inside)}."
            )
        return ModelRetry(
            f"{path!r} is a directory, and no file under it has an extension describe_callables "
            f"parses ({_SUPPORTED_EXTS}). Call list_files({rel_dir!r}) to see what is there and "
            "read_file on one of those paths instead."
        )
    # An absolute host path that lands inside the snapshot has an exact repo-relative form; one
    # outside it is never named or stat'ed, because that is the confinement boundary.
    if path.startswith("/"):
        absolute = Path(path).resolve()
        if absolute.is_relative_to(root):
            rel = absolute.relative_to(root).as_posix()
            lead = (f"{path!r} is an absolute path; describe_callables takes paths relative to "
                    f"the repository root, so this one is {rel!r}.")
            if absolute.is_file():
                return ModelRetry(f"{lead} Call describe_callables with {rel!r}.")
            if absolute.is_dir():
                inside = _supported_matches(ctx, rel or ".", "*")
                if inside:
                    return ModelRetry(f"{lead} It is a directory, so call describe_callables with "
                                      f"one file from it: {_name_them(inside)}.")
    lead = f"{path!r} does not exist in the repository"
    if "/" not in path and "." in path and Path(path).suffix.lower() not in _LANG_BY_SUFFIX:
        # `com.example.UserDao`: a fully-qualified class name, not a path.
        lead += (", and describe_callables takes a repo-relative FILE path, not a class or "
                 "package name")
    for stem in _likely_stems(path):
        same_name = _supported_matches(ctx, ".", f"{stem}.*")
        if len(same_name) == 1:
            return ModelRetry(f"{lead}. The file named {stem!r} in this repository is "
                              f"{same_name[0]!r}; call describe_callables with exactly that path.")
        if same_name:
            return ModelRetry(f"{lead}. The files named {stem!r} in this repository are "
                              f"{_name_them(same_name)}; call describe_callables with whichever "
                              "one the finding points at.")
    sources = _supported_matches(ctx, ".", "*")
    if sources:
        return ModelRetry(f"{lead}. The source files describe_callables can parse here are "
                          f"{_name_them(sources)}; call it again with one of those paths.")
    return ModelRetry(f"{lead}, and it holds no file with an extension describe_callables parses "
                      f"({_SUPPORTED_EXTS}). Use list_files('.') and read_file instead.")


def describe_callables(ctx: RunContext[AgentDeps], path: str) -> str:
    """Report the callable symbols a source file defines or exports, and how to reach them.

    For each symbol: name, kind (function / method / class / exported binding), parameters where
    the declaration reveals them, whether it is a named or default export, whether calling it
    needs an instance, and the literal import/require line a test should write. Call this before
    naming a target callable or writing an import; a named export requires destructuring and a
    default export must not be destructured, and reading the file does not make that obvious.

    `path` is a single repo-relative file path, spelled exactly as `list_files` prints it (e.g.
    src/main/java/com/example/UserDao.java) - never a class or package name, never an absolute
    path, never a directory.

    Supports .py (parsed with `ast`, so exact), .js/.jsx/.mjs/.cjs, .java and .pl/.pm/.t
    (heuristic text scan - the output states per language what is certain and what is inferred).
    Only symbols actually found in the file are reported; at most 80.
    """
    target, rel, language = describable_target(ctx, path)
    return describe_text(*_read_capped(target), rel, language)


def describable_target(ctx: RunContext[AgentDeps], path: str) -> tuple[Path, Path, str]:
    """(file, repo-relative path, language) for a path describe_callables accepts.

    Raises ModelRetry with a corrective message for anything else.
    """
    # Keep the corrective response useful without passing an absolute host path through the
    # shared resolver. `_not_a_file_retry` only inspects the supplied absolute path after proving
    # it is inside the repository; paths outside remain opaque.
    if Path(path).is_absolute():
        raise _not_a_file_retry(
            ctx, path, Path(ctx.deps.repo_path).resolve() / path.lstrip("/")
        )
    target = _resolve(ctx.deps.repo_path, path)
    if not target.is_file():
        raise _not_a_file_retry(ctx, path, target)
    rel = target.relative_to(Path(ctx.deps.repo_path).resolve())
    language = _LANG_BY_SUFFIX.get(target.suffix.lower())
    if language is None:
        same_stem = _supported_matches(ctx, ".", f"{target.stem}.*")
        instead = (f" If you meant the source that defines {target.stem!r}, that is "
                   f"{_name_them(same_stem)}." if same_stem else "")
        raise ModelRetry(
            f"{path!r} has no supported extension (got {target.suffix!r}; supported: "
            f"{_SUPPORTED_EXTS}). Use read_file({rel.as_posix()!r}) for this one.{instead}"
        )
    return target, rel, language


def describe_text(text: str, truncated_bytes: bool, rel: Path, language: str) -> str:
    """The describe_callables report for a file already read (at most MAX_FILE_BYTES of it)."""
    lines = text.splitlines()
    truncated_source = len(lines) > MAX_SYMBOL_SOURCE_LINES
    if truncated_source:
        text = "\n".join(lines[:MAX_SYMBOL_SOURCE_LINES])

    symbols, header = _EXTRACTORS[language](text, rel)
    out = [f"{rel.as_posix()}  language={language}  lines={len(lines)}",
           f"certainty: {_CERTAINTY[language]}"]
    if truncated_bytes:
        out.append(f"WARNING: the file is larger than {MAX_FILE_BYTES} bytes; only its first "
                   f"{len(lines)} lines were read.")
    if truncated_source:
        out.append(f"WARNING: only the first {MAX_SYMBOL_SOURCE_LINES} lines were scanned; "
                   "symbols below that line are not reported.")
    out.extend(header)
    shown = symbols[:MAX_SYMBOLS]
    out.append(f"symbols found: {len(symbols)}"
               + (f" (showing the first {MAX_SYMBOLS})" if len(symbols) > MAX_SYMBOLS else ""))
    if not shown:
        out.append("")
        out.append("(no callable symbols found - this file defines nothing a test can call "
                   "directly; look for the module that wraps it)")
        return "\n".join(out)
    for s in shown:
        where = f"line={s.line}" if s.line else "line=unknown"
        params = _clip(s.params) if s.params is not None else "(not determined)"
        out.append("")
        out.append(f"{_clip(s.name)}  kind={s.kind}  params={params}  {where}  "
                   f"export={_clip(s.export)}")
        out.append(f"  reach: {_clip(s.reach)}")
        out.extend(f"  note: {_clip(n)}" for n in s.notes)
    return clip_bytes("\n".join(out), MAX_DESCRIBE_BYTES)
