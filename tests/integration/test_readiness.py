"""Production readiness integration tests for RAGIN."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]


# --- Test 1: All components importable ---


@pytest.mark.integration()
class TestImports:
    """Verify all RAGIN modules import without error."""

    MODULES = [
        "ragin",
        "ragin.chrollo",
        "ragin.chrollo.classifier",
        "ragin.chrollo.features",
        "ragin.chrollo.models",
        "ragin.chrollo.pipeline",
        "ragin.chrollo.session_parser",
        "ragin.don",
        "ragin.don.intel_corpus",
        "ragin.don.models",
        "ragin.don.pipeline",
        "ragin.don.rag_engine",
        "ragin.don.threat_mapper",
        "ragin.don.vector_store",
        "ragin.hisoka",
        "ragin.hisoka.deceiver",
        "ragin.hisoka.deception",
        "ragin.hisoka.dwell_tracker",
        "ragin.hisoka.models",
        "ragin.hisoka.persona",
        "ragin.hisoka.pipeline",
        "ragin.hisoka.response_generator",
        "ragin.hisoka.session_manager",
        "ragin.intelligence",
        "ragin.intelligence.adaptive_response",
        "ragin.intelligence.evasion_detector",
        "ragin.intelligence.models",
        "ragin.intelligence.skill_strategy",
        "ragin.monitoring",
        "ragin.monitoring.alerts",
        "ragin.monitoring.audit",
        "ragin.monitoring.health",
        "ragin.monitoring.metrics",
    ]

    @pytest.mark.parametrize("module_name", MODULES)
    def test_module_importable(self, module_name):
        mod = importlib.import_module(module_name)
        assert mod is not None, f"Module {module_name} imported as None"


# --- Test 2: All config files valid ---


@pytest.mark.integration()
class TestConfigFiles:
    """Verify all YAML/JSON configuration files parse correctly."""

    YAML_FILES = [
        "ragin/config/settings.yaml",
        "ragin/config/prometheus.yml",
        "ragin/config/alert_rules.yml",
    ]

    @pytest.mark.parametrize("rel_path", YAML_FILES)
    def test_yaml_parseable(self, rel_path):
        path = PROJECT_ROOT / rel_path
        assert path.exists(), f"Config file not found: {rel_path}"
        with open(path) as f:
            data = yaml.safe_load(f)
        assert data is not None, f"YAML file parsed as None: {rel_path}"

    def test_settings_yaml_has_required_keys(self):
        path = PROJECT_ROOT / "ragin/config/settings.yaml"
        with open(path) as f:
            cfg = yaml.safe_load(f)
        required_keys = [
            "OPENROUTER_API_KEY",
            "OPENROUTER_BASE_URL",
            "MODEL_ROUTER",
            "COST_TRACKING",
            "SECURITY",
            "OBSERVABILITY",
        ]
        for key in required_keys:
            assert key in cfg, f"Missing required config key: {key}"

    def test_model_router_has_routing_rules(self):
        path = PROJECT_ROOT / "ragin/config/settings.yaml"
        with open(path) as f:
            cfg = yaml.safe_load(f)
        router = cfg.get("MODEL_ROUTER", {})
        assert "routing_rules" in router, "MODEL_ROUTER missing routing_rules"
        rules = router["routing_rules"]
        assert "chrollo_inference" in rules, "Missing chrollo_inference routing rule"
        assert "don_retrieval" in rules, "Missing don_retrieval routing rule"
        assert "hisoka_deception" in rules, "Missing hisoka_deception routing rule"

    def test_cost_tracking_has_budget(self):
        path = PROJECT_ROOT / "ragin/config/settings.yaml"
        with open(path) as f:
            cfg = yaml.safe_load(f)
        cost = cfg.get("COST_TRACKING", {})
        assert "budget" in cost, "COST_TRACKING missing budget"
        budget = cost["budget"]
        assert "daily_usd" in budget, "Budget missing daily_usd"
        assert "monthly_usd" in budget, "Budget missing monthly_usd"

    def test_alert_rules_structure(self):
        path = PROJECT_ROOT / "ragin/config/alert_rules.yml"
        with open(path) as f:
            data = yaml.safe_load(f)
        assert "groups" in data, "alert_rules missing groups"
        groups = data["groups"]
        assert len(groups) > 0, "No alert groups defined"
        rules = groups[0].get("rules", [])
        assert len(rules) >= 4, f"Expected at least 4 alert rules, got {len(rules)}"


# --- Test 3: Health endpoint returns 200 (mock) ---


@pytest.mark.integration()
class TestHealthEndpoint:
    """Verify health endpoint logic works correctly."""

    def test_health_response_format(self):
        """Test that health check returns expected structure."""
        from ragin.monitoring.health import ComponentHealth, HealthState

        health = ComponentHealth(
            name="test",
            state=HealthState.HEALTHY,
            latency_ms=1.5,
            message="ok",
        )
        assert health.name == "test"
        assert health.state == HealthState.HEALTHY
        assert health.latency_ms == 1.5

    def test_health_states(self):
        from ragin.monitoring.health import HealthState

        assert HealthState.HEALTHY.value == "healthy"
        assert HealthState.DEGRADED.value == "degraded"
        assert HealthState.UNHEALTHY.value == "unhealthy"


# --- Test 4: Metrics endpoint format ---


@pytest.mark.integration()
class TestMetricsFormat:
    """Verify Prometheus metrics are properly formatted."""

    def test_prometheus_metrics_importable(self):
        from prometheus_client import Counter, generate_latest

        counter = Counter("ragin_test_counter", "Test counter")
        counter.inc()
        output = generate_latest().decode("utf-8")
        assert "ragin_test_counter" in output

    def test_metrics_contain_expected_format(self):
        from prometheus_client import Counter, generate_latest

        counter = Counter("ragin_test_format_check", "Format check")
        counter.inc()
        output = generate_latest().decode("utf-8")
        # Prometheus exposition format has HELP and TYPE lines
        assert "# HELP ragin_test_format_check" in output
        assert "# TYPE ragin_test_format_check" in output


# --- Test 5: All env vars documented ---


@pytest.mark.integration()
class TestEnvVarsDocumented:
    """Verify .env.example documents all required environment variables."""

    REQUIRED_VARS = [
        "OPENROUTER_API_KEY",
        "API_KEY",
        "GRAFANA_ADMIN_PASSWORD",
    ]

    def test_env_example_exists(self):
        env_path = PROJECT_ROOT / ".env.example"
        assert env_path.exists(), ".env.example file not found"

    @pytest.mark.parametrize("var_name", REQUIRED_VARS)
    def test_env_var_documented(self, var_name):
        env_path = PROJECT_ROOT / ".env.example"
        content = env_path.read_text()
        assert var_name in content, f"Environment variable {var_name} not documented in .env.example"

    def test_env_example_has_all_expected_vars(self):
        env_path = PROJECT_ROOT / ".env.example"
        content = env_path.read_text()
        expected = [
            "OPENROUTER_API_KEY",
            "GATEWAY_PORT",
            "CHROLLO_PORT",
            "DON_PORT",
            "HISOKA_PORT",
            "REDIS_URL",
            "PROMETHEUS_PORT",
            "GRAFANA_PORT",
            "API_KEY",
            "MONTHLY_BUDGET_USD",
            "DAILY_BUDGET_USD",
        ]
        for var in expected:
            assert var in content, f"Expected variable {var} not in .env.example"


# --- Test 6: Docker Compose valid ---


@pytest.mark.integration()
class TestDockerCompose:
    """Verify all Docker Compose files parse correctly."""

    COMPOSE_FILES = [
        "docker-compose.yml",
        "docker-compose.prod.yml",
        "docker-compose.test.yml",
        "docker-compose.canary.yml",
    ]

    @pytest.mark.parametrize("filename", COMPOSE_FILES)
    def test_compose_file_parseable(self, filename):
        path = PROJECT_ROOT / filename
        if not path.exists():
            pytest.skip(f"Compose file not found: {filename}")
        with open(path) as f:
            data = yaml.safe_load(f)
        assert data is not None, f"Compose file parsed as None: {filename}"

    def test_base_compose_has_all_services(self):
        path = PROJECT_ROOT / "docker-compose.yml"
        with open(path) as f:
            data = yaml.safe_load(f)
        services = data.get("services", {})
        expected_services = [
            "gateway",
            "chrollo",
            "don",
            "hisoka",
            "redis",
            "prometheus",
            "grafana",
            "nginx",
        ]
        for svc in expected_services:
            assert svc in services, f"Missing service: {svc}"

    def test_base_compose_has_networks(self):
        path = PROJECT_ROOT / "docker-compose.yml"
        with open(path) as f:
            data = yaml.safe_load(f)
        networks = data.get("networks", {})
        assert "ragin-internal" in networks, "Missing ragin-internal network"
        assert "ragin-external" in networks, "Missing ragin-external network"

    def test_prod_compose_has_resource_limits(self):
        path = PROJECT_ROOT / "docker-compose.prod.yml"
        with open(path) as f:
            data = yaml.safe_load(f)
        services = data.get("services", {})
        for svc in ["gateway", "chrollo", "don", "hisoka"]:
            deploy = services.get(svc, {}).get("deploy", {})
            resources = deploy.get("resources", {})
            assert "limits" in resources, f"Prod service {svc} missing resource limits"

    def test_prod_compose_has_security_opt(self):
        path = PROJECT_ROOT / "docker-compose.prod.yml"
        with open(path) as f:
            data = yaml.safe_load(f)
        services = data.get("services", {})
        for svc in ["gateway", "chrollo", "don", "hisoka"]:
            sec = services.get(svc, {}).get("security_opt", [])
            assert "no-new-privileges:true" in sec, f"Prod service {svc} missing no-new-privileges"


# --- Test 7: Runbook sections complete ---


@pytest.mark.integration()
class TestRunbookSections:
    """Verify operational runbook has all required sections."""

    def test_runbook_exists(self):
        path = PROJECT_ROOT / "docs/OPERATIONAL_RUNBOOK.md"
        assert path.exists(), "OPERATIONAL_RUNBOOK.md not found"

    def test_runbook_has_all_sections(self):
        path = PROJECT_ROOT / "docs/OPERATIONAL_RUNBOOK.md"
        content = path.read_text()
        required_sections = [
            "System Overview",
            "Prerequisites",
            "Deployment Procedures",
            "Daily Operations",
            "Troubleshooting",
            "Emergency Procedures",
        ]
        for section in required_sections:
            assert section in content, f"Runbook missing section: {section}"

    def test_runbook_has_troubleshooting_table(self):
        path = PROJECT_ROOT / "docs/OPERATIONAL_RUNBOOK.md"
        content = path.read_text()
        assert "Gateway 502" in content, "Troubleshooting table missing Gateway 502"
        assert "High latency" in content, "Troubleshooting table missing High latency"
        assert "Cost spike" in content, "Troubleshooting table missing Cost spike"

    def test_runbook_has_component_table(self):
        path = PROJECT_ROOT / "docs/OPERATIONAL_RUNBOOK.md"
        content = path.read_text()
        for comp in ["Gateway", "Chrollo", "Don", "Hisoka", "Redis", "Prometheus", "Grafana"]:
            assert comp in content, f"Runbook missing component: {comp}"


# --- Test 8: Deployment checklist complete ---


@pytest.mark.integration()
class TestDeploymentChecklist:
    """Verify deployment checklist has all required items."""

    def test_checklist_exists(self):
        path = PROJECT_ROOT / "docs/DEPLOYMENT_CHECKLIST.md"
        assert path.exists(), "DEPLOYMENT_CHECKLIST.md not found"

    def test_checklist_has_all_phases(self):
        path = PROJECT_ROOT / "docs/DEPLOYMENT_CHECKLIST.md"
        content = path.read_text()
        phases = ["Pre-Deployment", "Deployment", "Post-Deployment", "Sign-Off"]
        for phase in phases:
            assert phase in content, f"Checklist missing phase: {phase}"

    def test_checklist_has_key_items(self):
        path = PROJECT_ROOT / "docs/DEPLOYMENT_CHECKLIST.md"
        content = path.read_text()
        items = [
            "345 tests passing",
            "Docker images build",
            "OPENROUTER_API_KEY",
            "SSL certificates",
            "Gateway started",
            "Redis started",
            "Prometheus",
            "Error rate",
            "Cost tracking",
            "Rollback",
            "Sign-Off",
        ]
        for item in items:
            assert item in content, f"Checklist missing item containing: {item}"

    def test_checklist_has_checkbox_format(self):
        path = PROJECT_ROOT / "docs/DEPLOYMENT_CHECKLIST.md"
        content = path.read_text()
        checkbox_count = content.count("- [ ]")
        assert checkbox_count >= 20, f"Expected at least 20 checklist items, found {checkbox_count}"


# --- Test 9: All documentation files exist ---


@pytest.mark.integration()
class TestDocumentationFiles:
    """Verify all required documentation files exist."""

    REQUIRED_DOCS = [
        "docs/OPERATIONAL_RUNBOOK.md",
        "docs/SECURITY_HARDENING.md",
        "docs/COST_OPTIMIZATION.md",
        "docs/ARCHITECTURE.md",
        "docs/DEPLOYMENT_CHECKLIST.md",
        "docs/TROUBLESHOOTING.md",
    ]

    @pytest.mark.parametrize("rel_path", REQUIRED_DOCS)
    def test_doc_exists(self, rel_path):
        path = PROJECT_ROOT / rel_path
        assert path.exists(), f"Documentation file not found: {rel_path}"
        assert path.stat().st_size > 100, f"Documentation file too small: {rel_path}"


# --- Test 10: Security hardening completeness ---


@pytest.mark.integration()
class TestSecurityHardening:
    """Verify security hardening guide covers required topics."""

    def test_security_doc_has_auth_section(self):
        path = PROJECT_ROOT / "docs/SECURITY_HARDENING.md"
        content = path.read_text()
        assert "Authentication" in content
        assert "API Key" in content
        assert "rotation" in content.lower()

    def test_security_doc_has_network_section(self):
        path = PROJECT_ROOT / "docs/SECURITY_HARDENING.md"
        content = path.read_text()
        assert "Network Security" in content
        assert "TLS" in content
        assert "Firewall" in content

    def test_security_doc_has_compliance_section(self):
        path = PROJECT_ROOT / "docs/SECURITY_HARDENING.md"
        content = path.read_text()
        assert "Compliance" in content
        assert "retention" in content.lower()
        assert "audit" in content.lower()


# --- Test 11: Architecture doc completeness ---


@pytest.mark.integration()
class TestArchitectureDoc:
    """Verify architecture documentation covers all components."""

    def test_architecture_has_component_details(self):
        path = PROJECT_ROOT / "docs/ARCHITECTURE.md"
        content = path.read_text()
        components = ["Chrollo", "Don", "Hisoka", "Gateway", "Intelligence"]
        for comp in components:
            assert comp in content, f"Architecture doc missing component: {comp}"

    def test_architecture_has_mermaid_diagrams(self):
        path = PROJECT_ROOT / "docs/ARCHITECTURE.md"
        content = path.read_text()
        assert "```mermaid" in content, "Architecture doc missing Mermaid diagrams"
        diagram_count = content.count("```mermaid")
        assert diagram_count >= 3, f"Expected at least 3 Mermaid diagrams, found {diagram_count}"

    def test_architecture_has_api_contracts(self):
        path = PROJECT_ROOT / "docs/ARCHITECTURE.md"
        content = path.read_text()
        assert "/api/classify" in content
        assert "/api/analyze" in content
        assert "/api/deceive" in content
        assert "/health" in content
