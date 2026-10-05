"""Where the runtime's own data files are, whether it runs from a checkout or a wheel.

agent-playbook 02 (Build and packaging) makes two requirements that this module exists to
satisfy, and that were both broken before it:

    Agent specifications, instruction files, and runtime `SKILL.md` files MUST be included as
    package data. ... Runtime resource paths SHOULD be resolved with `importlib.resources`, not
    a process working-directory assumption.

The previous arrangement did the opposite. Specs, skills and the model catalogue sat at the
repository root and were addressed as ``Path(__file__).parents[2] / "agents"`` -- which is the
repository root only when the package is imported from ``src/``. Installed as a wheel, that
expression resolves to ``site-packages/../..`` and none of the three directories exist there,
so every agent build failed on an installed copy. The wheel also shipped none of them, so
there was nothing for a corrected path to find.

Two roots, and the distinction is the whole point:

* **Package resources** (:func:`package_root`) are the things an agent *needs in order to run*
  -- its spec, the skills it may load, the approved-model catalogue. These ship in the wheel
  and are resolved through ``importlib.resources``.
* **Project files** (:func:`source_checkout`) are the things reviewers and CI read *about* the
  system -- the threat model, the eval corpus, the docs. They stay at the repository root and
  are simply absent from a deployment. Callers that need them must cope with ``None`` rather
  than assume a checkout.
"""
from __future__ import annotations

from functools import cache
from importlib.resources import files
from pathlib import Path


@cache
def package_root() -> Path:
    """The installed ``infosec_harness`` package directory.

    ``files()`` is used rather than ``__file__`` so the lookup goes through the import system
    that actually located the package. The cast to ``Path`` assumes a filesystem-backed
    install, which every deployment here is; a zipimported one would need the traversable API
    throughout, and would fail loudly here rather than silently resolving somewhere wrong.
    """
    return Path(str(files("infosec_harness")))


@cache
def source_checkout() -> Path | None:
    """The repository root when running from a source tree, else ``None``.

    Detected by the marker that only a checkout has -- ``pyproject.toml`` two levels above the
    package (``<root>/src/infosec_harness``). An installed wheel has no such ancestor, and the
    honest answer there is "there is no repository", not a path that happens to exist.
    """
    candidate = package_root().resolve().parents[1]
    return candidate if (candidate / "pyproject.toml").is_file() else None


def agents_dir() -> Path:
    """Agent specs: ``<package>/agents/<name>/agent.yaml``, the playbook's golden path."""
    return package_root() / "agents"


def skills_dir() -> Path:
    """Shared runtime skills: ``<package>/skills/<name>/SKILL.md``."""
    return package_root() / "skills"


def models_config() -> Path:
    """The approved-model catalogue. Governance data, so it ships with the code it governs."""
    return package_root() / "config" / "models.yaml"


def project_file(*parts: str) -> Path | None:
    """A repository file that is deliberately not packaged, or ``None`` off a checkout.

    Used for the threat model and the eval corpus: reviewable artifacts that a running
    deployment has no business reading.
    """
    root = source_checkout()
    return root.joinpath(*parts) if root else None
