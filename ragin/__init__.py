"""
RAGIN Cloud LLM Migration - Core Package

Three-component migration from 20-node Docker cluster to cloud-native services:
- Component A: Chrollo (Behavioral Classification) - ML service with feature store
- Component B: Don (Hybrid RAG Engine) - Vector DB + keyword search with RAG defenses
- Component C: Hisoka (Adaptive Deception Layer) - OpenRouter LLM with session isolation

Additional modules:
- Intelligence Cycle — closed feedback loop between Don (CTI analysis) and Hisoka (deception)
- Honeytoken Engine — canary token injection and trigger detection
- CTI Feed Connectors — MISP, AlienVault OTX, RSS/Atom, CISA KEV
- ATT&CK Heatmap — Navigator-compatible JSON layer generation
- SIEM/SOAR Integration — Splunk HEC, Elastic CEF, Syslog connectors
- Deception Effectiveness Benchmark — metrics, scoring, and comparative benchmarks
- Multi-Tenant RBAC — tenant isolation, role-based access control, audit logging
"""

__version__ = "1.0.0"
__components__ = ["chrollo", "don", "hisoka", "cycle", "intelligence", "siem", "benchmark", "auth"]
