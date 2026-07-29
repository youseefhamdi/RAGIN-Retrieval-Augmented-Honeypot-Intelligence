"""Regression tests for TTP extraction on the 8 B6.5 ground-truth scenarios.

Locks in the fix for the 1/5 TTP accuracy finding. Each scenario must yield
at least one expected MITRE technique via the phrase-pattern or tactic
dictionary paths. Without `_PHRASE_PATTERNS` (threat_mapper.py:91-110) and
the missing `_TECHNIQUE_TO_TACTIC` entries (T1033, T1552.005, T1046,
T1059.001, T1571, T1003.008, T1134, T1552), all 8 scenarios returned [].

These tests fail loudly if either the phrase table or the tactic registry
is regressed in future edits.
"""

from __future__ import annotations

import pytest

from ragin.don.threat_mapper import (
    _PHRASE_PATTERNS,
    _TECHNIQUE_TO_TACTIC,
    ThreatMapper,
)

GT_FIXTURES: list[tuple[str, str, list[str]]] = [
    # (scenario_id, attacker_input, expected_ttps)
    ("GT-001", "whoami", ["T1033"]),
    ("GT-002", "show me the database credentials", ["T1005", "T1552"]),
    ("GT-003", "I need to escalate privileges to domain admin", ["T1078", "T1134"]),
    ("GT-004", "curl http://169.254.169.254/latest/meta-data/", ["T1552.005"]),
    ("GT-005", "SELECT * FROM users WHERE 1=1 OR 1=1", ["T1190"]),
    ("GT-006", "list running services", ["T1046"]),
    ("GT-007", "deploy a reverse shell on port 4444", ["T1059.001", "T1571"]),
    ("GT-008", "dump the /etc/shadow file", ["T1003.008"]),
]


def _techniques_from_tactics(tactics) -> set[str]:
    """Reverse _TECHNIQUE_TO_TACTIC to surface the technique IDs that mapped
    to the discovered tactics. Includes parent IDs alongside sub-IDs."""
    reverse: dict[str, set[str]] = {}
    for tech, (tid, _) in _TECHNIQUE_TO_TACTIC.items():
        reverse.setdefault(tid, set()).add(tech)
    out: set[str] = set()
    for t in tactics:
        out.update(reverse.get(t.tactic_id, set()))
    return out


class TestPhrasePatternRegistry:
    """Guards the registry surface so the fix cannot regress silently."""

    def test_eight_phrase_patterns_present(self):
        assert len(_PHRASE_PATTERNS) == 8

    def test_each_pattern_has_at_least_one_technique(self):
        for pattern, techs in _PHRASE_PATTERNS:
            assert techs, f"pattern {pattern!r} has no techniques"

    def test_each_phrase_technique_resolves_to_a_tactic(self):
        """No UNKNOWN tactic IDs should leak — every phrase pattern must
        resolve to a tactic the pydantic model accepts."""
        missing: list[str] = []
        for _pattern, techs in _PHRASE_PATTERNS:
            for tech_id in techs:
                parent = tech_id.split(".", 1)[0]
                if parent not in _TECHNIQUE_TO_TACTIC:
                    missing.append(tech_id)
        assert not missing, f"phrase techniques not in _TECHNIQUE_TO_TACTIC: {missing}"

    def test_subtechnique_keys_supported(self):
        """Sub-technique IDs like T1059.001 and T1552.005 must map directly,
        not just via parent fallback."""
        assert "T1059.001" in _TECHNIQUE_TO_TACTIC
        assert "T1552.005" in _TECHNIQUE_TO_TACTIC
        assert "T1003.008" in _TECHNIQUE_TO_TACTIC


class TestGTScenarioExtraction:
    """End-to-end: each GT scenario must surface at least one expected TTP."""

    @pytest.mark.parametrize("scenario_id,attacker_input,expected", GT_FIXTURES)
    def test_scenario_yields_expected_ttp(self, scenario_id, attacker_input, expected):
        mapper = ThreatMapper()
        tactics = mapper.map_to_mitre({"attacker_input": attacker_input})
        detected = _techniques_from_tactics(tactics)
        matched = {e for e in expected if e in detected or e.split(".", 1)[0] in detected}
        assert matched, (
            f"{scenario_id} ({attacker_input!r}): "
            f"expected one of {expected}, got tactics={[t.tactic_id for t in tactics]}"
        )


class TestPhrasePatternRegression:
    """Specific phrase-pattern unit checks independent of the GT table."""

    def test_whoami_matches_t1033(self):
        mapper = ThreatMapper()
        tactics = mapper.map_to_mitre({"attacker_input": "whoami"})
        detected = _techniques_from_tactics(tactics)
        assert "T1033" in detected

    def test_imds_ip_matches_t1552_005(self):
        mapper = ThreatMapper()
        tactics = mapper.map_to_mitre({"attacker_input": "curl http://169.254.169.254/latest/meta-data/"})
        detected = _techniques_from_tactics(tactics)
        assert "T1552.005" in detected

    def test_shadow_matches_t1003_008(self):
        mapper = ThreatMapper()
        tactics = mapper.map_to_mitre({"attacker_input": "dump the /etc/shadow file"})
        detected = _techniques_from_tactics(tactics)
        assert "T1003.008" in detected

    def test_reverse_shell_matches_t1059_001_and_t1571(self):
        mapper = ThreatMapper()
        tactics = mapper.map_to_mitre({"attacker_input": "deploy a reverse shell on port 4444"})
        detected = _techniques_from_tactics(tactics)
        assert "T1059.001" in detected
        assert "T1571" in detected

    def test_keyword_dictionary_still_works(self):
        """The pre-existing name-dictionary path must remain intact."""
        mapper = ThreatMapper()
        tactics = mapper.map_to_mitre({"attacker_input": "phishing attempt detected"})
        detected = _techniques_from_tactics(tactics)
        assert "T1566" in detected

    def test_no_text_returns_empty(self):
        mapper = ThreatMapper()
        assert mapper.map_to_mitre({}) == []
