"""The adapter profile each detected language maps to, recorded in the execution manifest.

Every profile is ``experimental``: detection and the adapter contract
(``ecosystem_contract.ADAPTER_CONTRACT_VERSION``) do not by themselves establish tested support.
"""

from __future__ import annotations

from collections.abc import Mapping

from infosec_harness.domain.models import SupportStatus

# language -> adapter profile id.
ECOSYSTEM_PROFILES: Mapping[str, str] = {
    "python": "python-unit-probe",
    "java": "jvm-unit-probe",
    "javascript": "javascript-unit-probe",
    "perl": "perl-unit-probe",
}
_LANGUAGE_PROFILE_ALIASES = {"typescript": "javascript"}


def profile_manifest(languages: Mapping[str, int]) -> dict:
    """Return recognized profile identities and explicit unsupported language observations."""
    present = sorted(language for language, count in languages.items() if count > 0)
    canonical = {language: _LANGUAGE_PROFILE_ALIASES.get(language, language)
                 for language in present}
    profiles = [{"id": ECOSYSTEM_PROFILES[language], "support": SupportStatus.experimental.value}
                for language in sorted(set(canonical.values()) & set(ECOSYSTEM_PROFILES))]
    unmapped = [{"language": language, "support": SupportStatus.unsupported.value}
                for language in present if canonical[language] not in ECOSYSTEM_PROFILES]
    return {"profiles": profiles, "unmapped_languages": unmapped}
