"""Chrollo — Behavioral Classification Layer (Phase 2.2).

Random Forest classifier that assesses attacker skill level from honeypot
session logs. Outputs one of four tiers (Novice / Intermediate / Expert / APT)
with confidence scores and routes escalations to Don and Hisoka components.
"""

from ragin.chrollo.classifier import (
    ChrolloClassifier,
    ClassificationResult,
)
from ragin.chrollo.features import FEATURE_NAMES, FeatureExtractor
from ragin.chrollo.models import (
    CommandEntry,
    FileOperation,
    NetworkActivity,
    SessionLog,
    SkillLevel,
)
from ragin.chrollo.pipeline import ChrolloPipeline
from ragin.chrollo.session_parser import SessionLogParser

__all__ = [
    "ChrolloClassifier",
    "ChrolloPipeline",
    "ClassificationResult",
    "CommandEntry",
    "FEATURE_NAMES",
    "FeatureExtractor",
    "FileOperation",
    "NetworkActivity",
    "SessionLog",
    "SessionLogParser",
    "SkillLevel",
]
