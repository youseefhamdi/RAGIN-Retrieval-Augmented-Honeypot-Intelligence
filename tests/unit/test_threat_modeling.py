"""Tests for ragin/cycle/threat_modeling.py — STRIDE analysis, findings, attack chains."""

from __future__ import annotations

from ragin.cycle.threat_modeling import (
    AttackChain,
    AttackChainBuilder,
    AttackChainStep,
    FindingSeverity,
    FindingStatus,
    MitreMapping,
    StrideCategory,
    StrideThreat,
    StructuredFinding,
    ThreatModel,
    ThreatModeler,
    ThreatModelResponseVerifier,
    VerificationResult,
    _compute_overall_risk,
    _estimate_sophistication,
    _map_ttp_to_mitre,
)

# ── StrideCategory ─────────────────────────────────────────────────────


class TestStrideCategory:
    def test_all_values(self):
        expected = {
            "spoofing",
            "tampering",
            "repudiation",
            "info_disclosure",
            "denial_of_service",
            "elevation_of_privilege",
        }
        assert {c.value for c in StrideCategory} == expected

    def test_str_enum(self):
        assert isinstance(StrideCategory.SPOOFING, str)
        assert StrideCategory.SPOOFING == "spoofing"


# ── StrideThreat ───────────────────────────────────────────────────────


class TestStrideThreat:
    def test_creation(self):
        t = StrideThreat(
            category=StrideCategory.SPOOFING,
            risk_level="high",
            confidence=0.7,
            evidence=["curl localhost"],
            description="test",
            mitigation="use mfa",
        )
        assert t.category == StrideCategory.SPOOFING
        assert t.risk_level == "high"
        assert t.confidence == 0.7
        assert t.evidence == ["curl localhost"]

    def test_to_dict(self):
        t = StrideThreat(
            category=StrideCategory.TAMPERING,
            risk_level="low",
            confidence=0.3,
        )
        d = t.to_dict()
        assert d["category"] == "tampering"
        assert d["risk_level"] == "low"
        assert d["confidence"] == 0.3
        assert d["evidence"] == []
        assert d["mitigation"] == ""

    def test_from_dict_roundtrip(self):
        t = StrideThreat(
            category=StrideCategory.INFO_DISCLOSURE,
            risk_level="critical",
            confidence=0.95,
            evidence=["cat /etc/passwd"],
            description="test desc",
            mitigation="minimize leakage",
        )
        d = t.to_dict()
        restored = StrideThreat.from_dict(d)
        assert restored.category == t.category
        assert restored.risk_level == t.risk_level
        assert restored.confidence == t.confidence
        assert restored.evidence == t.evidence
        assert restored.description == t.description
        assert restored.mitigation == t.mitigation


# ── ThreatModel ────────────────────────────────────────────────────────


class TestThreatModel:
    def _make_threat(self, risk: str, confidence: float = 0.5) -> StrideThreat:
        return StrideThreat(
            category=StrideCategory.SPOOFING,
            risk_level=risk,
            confidence=confidence,
        )

    def test_empty(self):
        m = ThreatModel(session_id="ses-1")
        assert m.threat_count == 0
        assert m.high_risk_threats == []
        assert m.max_confidence == 0.0
        assert m.overall_risk == "low"

    def test_threat_count(self):
        m = ThreatModel(
            session_id="ses-1",
            threats=[
                self._make_threat("low"),
                self._make_threat("high"),
                self._make_threat("medium"),
            ],
        )
        assert m.threat_count == 3

    def test_high_risk_threats(self):
        m = ThreatModel(
            session_id="ses-1",
            threats=[
                self._make_threat("low"),
                self._make_threat("high"),
                self._make_threat("critical"),
                self._make_threat("medium"),
            ],
        )
        hr = m.high_risk_threats
        assert len(hr) == 2
        assert all(t.risk_level in ("high", "critical") for t in hr)

    def test_max_confidence(self):
        m = ThreatModel(
            session_id="ses-1",
            threats=[
                self._make_threat("low", 0.3),
                self._make_threat("high", 0.9),
            ],
        )
        assert m.max_confidence == 0.9

    def test_to_dict(self):
        m = ThreatModel(
            session_id="ses-1",
            threats=[self._make_threat("high", 0.7)],
            overall_risk="high",
            attacker_input="whoami",
        )
        d = m.to_dict()
        assert d["session_id"] == "ses-1"
        assert d["threat_count"] == 1
        assert d["high_risk_count"] == 1
        assert d["overall_risk"] == "high"
        assert d["attacker_input"] == "whoami"
        assert "timestamp" in d


# ── FindingSeverity / FindingStatus ────────────────────────────────────


class TestFindingEnums:
    def test_severity_values(self):
        expected = {"info", "low", "medium", "high", "critical"}
        assert {s.value for s in FindingSeverity} == expected

    def test_status_values(self):
        expected = {"confirmed", "suspected", "false_positive"}
        assert {s.value for s in FindingStatus} == expected


# ── MitreMapping ───────────────────────────────────────────────────────


class TestMitreMapping:
    def test_creation(self):
        m = MitreMapping(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="execution",
            sub_technique="PowerShell",
            url="https://attack.mitre.org/techniques/T1059/001",
        )
        assert m.technique_id == "T1059.001"
        assert m.tactic == "execution"

    def test_to_dict(self):
        m = MitreMapping(
            technique_id="T1033",
            technique_name="System Owner/User Discovery",
            tactic="discovery",
        )
        d = m.to_dict()
        assert d["technique_id"] == "T1033"
        assert d["sub_technique"] == ""
        assert d["url"] == ""

    def test_from_dict_roundtrip(self):
        m = MitreMapping(
            technique_id="T1003",
            technique_name="OS Credential Dumping",
            tactic="credential_access",
            sub_technique="LSASS",
            url="https://attack.mitre.org/techniques/T1003",
        )
        restored = MitreMapping.from_dict(m.to_dict())
        assert restored.technique_id == m.technique_id
        assert restored.technique_name == m.technique_name
        assert restored.tactic == m.tactic
        assert restored.sub_technique == m.sub_technique
        assert restored.url == m.url


# ── StructuredFinding ──────────────────────────────────────────────────


class TestStructuredFinding:
    def _make_finding(self) -> StructuredFinding:
        return StructuredFinding(
            finding_id="F001",
            title="Credential Dump Attempt",
            severity=FindingSeverity.HIGH,
            confidence=0.85,
            status=FindingStatus.CONFIRMED,
            description="Attacker ran cat /etc/shadow",
            mitre_mappings=[
                MitreMapping("T1003", "OS Credential Dumping", "credential_access"),
            ],
            evidence=["cat /etc/shadow"],
            recommendations=["Enable audit logging"],
            session_id="ses-1",
            source_ip="10.0.0.1",
        )

    def test_mitre_technique_ids(self):
        f = self._make_finding()
        assert f.mitre_technique_ids == ["T1003"]

    def test_mitre_tactics(self):
        f = self._make_finding()
        assert f.mitre_tactics == ["credential_access"]

    def test_mitre_tactics_deduplication(self):
        f = StructuredFinding(
            finding_id="F002",
            title="Multi-tactic",
            severity=FindingSeverity.MEDIUM,
            confidence=0.5,
            mitre_mappings=[
                MitreMapping("T1033", "User Discovery", "discovery"),
                MitreMapping("T1082", "System Info", "discovery"),
                MitreMapping("T1003", "Credential Dump", "credential_access"),
            ],
        )
        assert sorted(f.mitre_tactics) == ["credential_access", "discovery"]

    def test_to_dict(self):
        f = self._make_finding()
        d = f.to_dict()
        assert d["finding_id"] == "F001"
        assert d["severity"] == "high"
        assert d["confidence"] == 0.85
        assert d["status"] == "confirmed"
        assert len(d["mitre_mappings"]) == 1
        assert "timestamp" in d
        assert d["source_ip"] == "10.0.0.1"

    def test_from_dict_roundtrip(self):
        f = self._make_finding()
        restored = StructuredFinding.from_dict(f.to_dict())
        assert restored.finding_id == f.finding_id
        assert restored.title == f.title
        assert restored.severity == f.severity
        assert restored.confidence == f.confidence
        assert len(restored.mitre_mappings) == 1
        assert restored.mitre_mappings[0].technique_id == "T1003"


# ── _compute_overall_risk ──────────────────────────────────────────────


class TestComputeOverallRisk:
    def test_empty(self):
        assert _compute_overall_risk([]) == "low"

    def test_single_low(self):
        t = [StrideThreat(StrideCategory.SPOOFING, "low", 0.3)]
        assert _compute_overall_risk(t) == "low"

    def test_single_critical(self):
        t = [StrideThreat(StrideCategory.SPOOFING, "critical", 0.9)]
        assert _compute_overall_risk(t) == "critical"

    def test_high_max_score(self):
        t = [StrideThreat(StrideCategory.SPOOFING, "high", 0.8)]
        assert _compute_overall_risk(t) == "high"

    def test_weighted_average_medium(self):
        t = [
            StrideThreat(StrideCategory.SPOOFING, "medium", 0.8),
            StrideThreat(StrideCategory.TAMPERING, "low", 0.3),
        ]
        result = _compute_overall_risk(t)
        # weighted avg: (2*0.8 + 1*0.3)/2 = 0.95 → below 1.5 → depends on max_score
        # max_score=2 (medium), avg=0.95 < 1.5 → low
        assert result == "low"

    def test_many_high_threats_push_to_critical(self):
        t = [
            StrideThreat(StrideCategory.SPOOFING, "high", 0.9),
            StrideThreat(StrideCategory.TAMPERING, "high", 0.9),
            StrideThreat(StrideCategory.INFO_DISCLOSURE, "high", 0.9),
        ]
        # weighted avg = 3*0.9 = 2.7 → ≥ 2.5 → high
        result = _compute_overall_risk(t)
        assert result == "high"


# ── ThreatModeler ──────────────────────────────────────────────────────


class TestThreatModeler:
    def setup_method(self):
        self.modeler = ThreatModeler()

    def test_analyze_empty_input(self):
        ctx = {"session_id": "ses-1"}
        m = self.modeler.analyze("", ctx)
        assert isinstance(m, ThreatModel)
        assert m.session_id == "ses-1"
        # Empty input should produce no threats
        assert m.threat_count == 0

    def test_info_disclosure_whoami(self):
        m = self.modeler.analyze("whoami", {"session_id": "ses-1"})
        # whoami matches INFO_DISCLOSURE pattern
        categories = {t.category for t in m.threats}
        assert StrideCategory.INFO_DISCLOSURE in categories

    def test_credential_dump(self):
        m = self.modeler.analyze("cat /etc/shadow", {"session_id": "ses-1"})
        categories = {t.category for t in m.threats}
        assert StrideCategory.INFO_DISCLOSURE in categories

    def test_elevation_of_privilege(self):
        m = self.modeler.analyze("sudo -l", {"session_id": "ses-1"})
        categories = {t.category for t in m.threats}
        assert StrideCategory.ELEVATION_OF_PRIVILEGE in categories

    def test_denial_of_service(self):
        m = self.modeler.analyze(":(){ :|:& };:", {"session_id": "ses-1"})
        categories = {t.category for t in m.threats}
        assert StrideCategory.DENIAL_OF_SERVICE in categories

    def test_skill_level_boost(self):
        m_novice = self.modeler.analyze("whoami", {"session_id": "ses-1", "skill_level": "novice"})
        m_apt = self.modeler.analyze("whoami", {"session_id": "ses-1", "skill_level": "apt"})
        # APT should have higher confidence than novice for same input
        novice_disc = next(t for t in m_novice.threats if t.category == StrideCategory.INFO_DISCLOSURE)
        apt_disc = next(t for t in m_apt.threats if t.category == StrideCategory.INFO_DISCLOSURE)
        assert apt_disc.confidence >= novice_disc.confidence

    def test_observed_ttps_add_threats(self):
        ctx = {
            "session_id": "ses-1",
            "observed_ttps": ["T1033", "T1003"],
        }
        m = self.modeler.analyze("whoami", ctx)
        categories = {t.category for t in m.threats}
        # T1033 → INFO_DISCLOSURE, T1003 → ELEVATION_OF_PRIVILEGE
        assert StrideCategory.INFO_DISCLOSURE in categories
        assert StrideCategory.ELEVATION_OF_PRIVILEGE in categories

    def test_observed_ttps_boost_existing(self):
        # T1033 maps to INFO_DISCLOSURE which "whoami" also matches
        ctx = {
            "session_id": "ses-1",
            "observed_ttps": ["T1033"],
        }
        m = self.modeler.analyze("whoami", ctx)
        disc_threats = [t for t in m.threats if t.category == StrideCategory.INFO_DISCLOSURE]
        assert len(disc_threats) == 1
        # Evidence should include the TTP
        assert any("T1033" in e for e in disc_threats[0].evidence)

    def test_overall_risk_reflected(self):
        m = self.modeler.analyze(":(){ :|:& };:", {"session_id": "ses-1"})
        # Fork bomb → DENIAL_OF_SERVICE → critical/high
        assert m.overall_risk in ("medium", "high", "critical")

    def test_recon_commands(self):
        m = self.modeler.analyze("nmap -sS 192.168.1.0/24", {"session_id": "ses-1"})
        categories = {t.category for t in m.threats}
        assert StrideCategory.INFO_DISCLOSURE in categories

    def test_persistence(self):
        m = self.modeler.analyze("crontab -e", {"session_id": "ses-1"})
        categories = {t.category for t in m.threats}
        assert StrideCategory.ELEVATION_OF_PRIVILEGE in categories


# ── VerificationResult ─────────────────────────────────────────────────


class TestVerificationResult:
    def test_creation(self):
        v = VerificationResult(
            passed=True,
            confidence=0.9,
            issues=[],
            recommendations=["use mfa"],
        )
        assert v.passed is True
        assert v.confidence == 0.9

    def test_to_dict(self):
        v = VerificationResult(
            passed=False,
            confidence=0.4,
            issues=["too long"],
            recommendations=["shorten"],
        )
        d = v.to_dict()
        assert d["passed"] is False
        assert d["issues"] == ["too long"]
        assert d["recommendations"] == ["shorten"]


# ── ThreatModelResponseVerifier ────────────────────────────────────────


class TestThreatModelResponseVerifier:
    def setup_method(self):
        self.verifier = ThreatModelResponseVerifier()

    def test_valid_response_passes(self):
        resp = {"response_text": "Welcome, user.", "persona_used": "linux_admin"}
        ctx = {"skill_level": "novice"}
        r = self.verifier.verify(resp, ctx)
        assert r["passed"] is True
        assert r["confidence"] >= 0.8

    def test_honeypot_indicator_fails(self):
        resp = {"response_text": "This is a honeypot! You are being monitored."}
        ctx = {}
        r = self.verifier.verify(resp, ctx)
        assert r["passed"] is False
        assert any("honeypot" in i.lower() for i in r["issues"])

    def test_empty_response_fails(self):
        resp = {"response_text": ""}
        ctx = {}
        r = self.verifier.verify(resp, ctx)
        assert r["passed"] is False
        assert any("empty" in i.lower() for i in r["issues"])

    def test_excessively_long_response(self):
        resp = {"response_text": "x" * 3000}
        ctx = {}
        r = self.verifier.verify(resp, ctx)
        assert any("long" in i.lower() for i in r["issues"])

    def test_expert_short_response_recommends_more(self):
        resp = {"response_text": "ok"}
        ctx = {"skill_level": "expert"}
        r = self.verifier.verify(resp, ctx)
        assert any("expert" in rec.lower() for rec in r["recommendations"])

    def test_high_threat_consider_more_deception(self):
        resp = {"response_text": "Error: not found"}
        ctx = {
            "threat_model": {"overall_risk": "high"},
        }
        r = self.verifier.verify(resp, ctx)
        assert any("deceptive" in rec.lower() for rec in r["recommendations"])

    def test_unknown_persona_recommends_check(self):
        resp = {"response_text": "Hello", "persona_used": "alien_overlord"}
        ctx = {}
        r = self.verifier.verify(resp, ctx)
        assert any("persona" in rec.lower() for rec in r["recommendations"])

    def test_valid_persona_no_warning(self):
        resp = {"response_text": "Hello", "persona_used": "linux_admin"}
        ctx = {}
        r = self.verifier.verify(resp, ctx)
        assert not any("persona" in rec.lower() for rec in r["recommendations"])


# ── AttackChainStep ────────────────────────────────────────────────────


class TestAttackChainStep:
    def test_creation(self):
        s = AttackChainStep(
            step_index=1,
            technique_id="T1033",
            technique_name="User Discovery",
            tactic="discovery",
            evidence="whoami",
            confidence=0.8,
        )
        assert s.step_index == 1
        assert s.technique_id == "T1033"

    def test_to_dict(self):
        s = AttackChainStep(
            step_index=1,
            technique_id="T1033",
            technique_name="User Discovery",
            tactic="discovery",
        )
        d = s.to_dict()
        assert d["step_index"] == 1
        assert d["technique_id"] == "T1033"
        assert d["confidence"] == 0.0


# ── AttackChain ────────────────────────────────────────────────────────


class TestAttackChain:
    def _make_chain(self, steps: list[AttackChainStep] | None = None) -> AttackChain:
        if steps is None:
            steps = [
                AttackChainStep(1, "T1033", "User Discovery", "discovery"),
                AttackChainStep(2, "T1082", "System Info", "discovery"),
            ]
        return AttackChain(
            session_id="ses-1",
            steps=steps,
            kill_chain_phases=["discovery"],
            confidence=0.7,
        )

    def test_step_count(self):
        c = self._make_chain()
        assert c.step_count == 2

    def test_tactics_covered(self):
        c = self._make_chain()
        assert c.tactics_covered == ["discovery"]

    def test_duration_estimate_quick_probe(self):
        steps = [AttackChainStep(i, f"T{i}", f"Name{i}", "discovery") for i in range(3)]
        c = AttackChain(session_id="ses-1", steps=steps)
        assert c.duration_estimate == "quick_probe"

    def test_duration_estimate_focused_attack(self):
        steps = [AttackChainStep(i, f"T{i}", f"Name{i}", "discovery") for i in range(8)]
        c = AttackChain(session_id="ses-1", steps=steps)
        assert c.duration_estimate == "focused_attack"

    def test_duration_estimate_extended_campaign(self):
        steps = [AttackChainStep(i, f"T{i}", f"Name{i}", "discovery") for i in range(15)]
        c = AttackChain(session_id="ses-1", steps=steps)
        assert c.duration_estimate == "extended_campaign"

    def test_duration_estimate_persistent_presence(self):
        steps = [AttackChainStep(i, f"T{i}", f"Name{i}", "discovery") for i in range(20)]
        c = AttackChain(session_id="ses-1", steps=steps)
        assert c.duration_estimate == "persistent_presence"

    def test_to_dict(self):
        c = self._make_chain()
        d = c.to_dict()
        assert d["session_id"] == "ses-1"
        assert d["step_count"] == 2
        assert d["tactics_covered"] == ["discovery"]
        assert d["duration_estimate"] == "quick_probe"


# ── _estimate_sophistication ───────────────────────────────────────────


class TestEstimateSophistication:
    def test_empty(self):
        assert _estimate_sophistication([]) == "unknown"

    def test_novice(self):
        steps = [AttackChainStep(1, "T1033", "User Discovery", "discovery")]
        assert _estimate_sophistication(steps) == "novice"

    def test_intermediate(self):
        steps = [AttackChainStep(i, f"T{i}", f"Name{i}", "discovery") for i in range(4)]
        assert _estimate_sophistication(steps) == "intermediate"

    def test_expert(self):
        tactics = ["defense_evasion", "credential_access"]
        steps = [AttackChainStep(i, f"T{i}", f"Name{i}", t) for i, t in enumerate(tactics)] + [
            AttackChainStep(i, f"T{i}", f"Name{i}", "discovery") for i in range(2, 8)
        ]
        assert _estimate_sophistication(steps) == "expert"

    def test_apt(self):
        apt_tactics = ["defense_evasion", "credential_access", "lateral_movement", "exfiltration"]
        steps = [AttackChainStep(i, f"T{i}", f"Name{i}", t) for i, t in enumerate(apt_tactics)] + [
            AttackChainStep(i, f"T{i}", f"Name{i}", "discovery") for i in range(4, 12)
        ]
        assert _estimate_sophistication(steps) == "apt"


# ── AttackChainBuilder ─────────────────────────────────────────────────


class TestAttackChainBuilder:
    def setup_method(self):
        self.builder = AttackChainBuilder()

    def test_build_empty(self):
        chain = self.builder.build("ses-1", [])
        assert chain.step_count == 0
        assert chain.attacker_sophistication == "unknown"
        assert chain.confidence == 0.0

    def test_build_single_ttp(self):
        ttps = [{"technique_id": "T1033", "technique_name": "User Discovery", "tactic": "discovery"}]
        chain = self.builder.build("ses-1", ttps)
        assert chain.step_count == 1
        assert chain.steps[0].technique_id == "T1033"
        assert chain.kill_chain_phases == ["discovery"]

    def test_build_sorts_by_kill_chain_order(self):
        ttps = [
            {"technique_id": "T1003", "technique_name": "Credential Dump", "tactic": "credential_access"},
            {"technique_id": "T1033", "technique_name": "User Discovery", "tactic": "discovery"},
            {"technique_id": "T1059", "technique_name": "Scripting", "tactic": "execution"},
        ]
        chain = self.builder.build("ses-1", ttps)
        # Kill chain order: execution → credential_access → discovery
        assert chain.steps[0].tactic == "execution"
        assert chain.steps[1].tactic == "credential_access"
        assert chain.steps[2].tactic == "discovery"

    def test_build_reindexes_after_sort(self):
        ttps = [
            {"technique_id": "T1003", "technique_name": "Credential Dump", "tactic": "credential_access"},
            {"technique_id": "T1033", "technique_name": "User Discovery", "tactic": "discovery"},
        ]
        chain = self.builder.build("ses-1", ttps)
        assert chain.steps[0].step_index == 1
        assert chain.steps[1].step_index == 2

    def test_build_confidence_average(self):
        ttps = [
            {"technique_id": "T1033", "tactic": "discovery", "confidence": 0.8},
            {"technique_id": "T1082", "tactic": "discovery", "confidence": 0.6},
        ]
        chain = self.builder.build("ses-1", ttps)
        assert chain.confidence == 0.7

    def test_build_from_session_context(self):
        ctx = {
            "observed_ttps": ["T1033", "T1082"],
        }
        chain = self.builder.build_from_session_context("ses-1", ctx)
        assert chain.step_count == 2
        assert chain.steps[0].technique_id == "T1033"

    def test_build_from_session_context_with_ttp_history(self):
        ctx = {
            "ttp_history": [
                {"technique_id": "T1003", "technique_name": "Credential Dump", "tactic": "credential_access"},
            ],
        }
        chain = self.builder.build_from_session_context("ses-1", ctx)
        assert chain.step_count == 1
        assert chain.steps[0].tactic == "credential_access"

    def test_build_from_session_context_empty(self):
        chain = self.builder.build_from_session_context("ses-1", {})
        assert chain.step_count == 0

    def test_build_from_session_context_unknown_ttp_ignored(self):
        ctx = {"observed_ttps": ["T9999"]}
        chain = self.builder.build_from_session_context("ses-1", ctx)
        assert chain.step_count == 0


# ── _map_ttp_to_mitre ──────────────────────────────────────────────────


class TestMapTtpToMitre:
    def test_known_technique(self):
        m = _map_ttp_to_mitre("T1033")
        assert m is not None
        assert m.technique_id == "T1033"
        assert m.tactic == "discovery"

    def test_unknown_technique(self):
        m = _map_ttp_to_mitre("T9999")
        assert m is None

    def test_credential_dump(self):
        m = _map_ttp_to_mitre("T1003")
        assert m is not None
        assert m.tactic == "credential_access"
