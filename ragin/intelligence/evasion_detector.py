"""Evasion detection — identifies when attackers probe for honeypot markers."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from ragin.intelligence.models import (
    AdjustmentRecommendation,
    EvasionIndicator,
    EvasionIndicatorType,
    EvasionResult,
)

logger = logging.getLogger(__name__)

_TOOL_PATTERNS: list[tuple[str, EvasionIndicatorType]] = [
    (r"nmap\s", EvasionIndicatorType.TOOL_SIGNATURE),
    (r"masscan\s", EvasionIndicatorType.TOOL_SIGNATURE),
    (r"metasploit", EvasionIndicatorType.TOOL_SIGNATURE),
    (r"msfconsole", EvasionIndicatorType.TOOL_SIGNATURE),
    (r"burpsuite|burp\s", EvasionIndicatorType.TOOL_SIGNATURE),
    (r"sqlmap\s", EvasionIndicatorType.TOOL_SIGNATURE),
    (r"nikto\s", EvasionIndicatorType.TOOL_SIGNATURE),
    (r"gobuster\s", EvasionIndicatorType.TOOL_SIGNATURE),
    (r"dirb\s", EvasionIndicatorType.TOOL_SIGNATURE),
    (r"wfuzz\s", EvasionIndicatorType.TOOL_SIGNATURE),
]

_FINGERPRINT_PATTERNS: list[tuple[str, EvasionIndicatorType]] = [
    (r"(cat|type)\s+/etc/(passwd|shadow|issue)", EvasionIndicatorType.FINGERPRINTING),
    (r"uname\s+-a", EvasionIndicatorType.FINGERPRINTING),
    (r"hostnamectl", EvasionIndicatorType.FINGERPRINTING),
    (r"lsb_release", EvasionIndicatorType.FINGERPRINTING),
    (r"cat\s+/proc/version", EvasionIndicatorType.FINGERPRINTING),
    (r"systemctl\s+list-units", EvasionIndicatorType.FINGERPRINTING),
]

_SANDBOX_PATTERNS: list[tuple[str, EvasionIndicatorType]] = [
    (r"vm(ware|detect)|virtualbox|qemu|xen", EvasionIndicatorType.SANDBOX_DETECTION),
    (r"dmesg.*\b(kvm|vmware|hyper-v)\b", EvasionIndicatorType.SANDBOX_DETECTION),
    (r"cat\s+/sys/class/dmi/id/product_name", EvasionIndicatorType.SANDBOX_DETECTION),
    (r"mac\s+address|ifconfig\s+eth0", EvasionIndicatorType.SANDBOX_DETECTION),
]

_DECEPTION_AWARE_PATTERNS: list[tuple[str, EvasionIndicatorType]] = [
    (r"honeypot|deception|fake|trap|canary", EvasionIndicatorType.DECEPTION_AWARE),
    (r"is\s+this\s+(real|genuine|legitimate)", EvasionIndicatorType.DECEPTION_AWARE),
    (r"(test|check)\s+(if|whether)\s+(this|it)\s+(is|was)\s+(real|fake)", EvasionIndicatorType.DECEPTION_AWARE),
]

_AUTO_SPEED_THRESHOLD_S = 0.5
_MIN_COMMANDS_FOR_SPEED = 3
_DETECTION_CONFIDENCE_THRESHOLD = 0.4

_CUMULATIVE_CONFIDENCE_THRESHOLD = 0.6


def _extract_commands(session_log: dict) -> list[str]:
    """Extract command strings from session log dict."""
    commands: list[str] = []
    for entry in session_log.get("commands", []):
        if isinstance(entry, dict):
            cmd = entry.get("command", "")
            if cmd:
                commands.append(cmd)
        elif isinstance(entry, str):
            commands.append(entry)
    return commands


def _check_tool_signatures(commands: list[str]) -> list[EvasionIndicator]:
    indicators: list[EvasionIndicator] = []
    for cmd in commands:
        for pattern, itype in _TOOL_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                indicators.append(
                    EvasionIndicator(
                        indicator_type=itype,
                        evidence=cmd[:256],
                        confidence=0.8,
                    )
                )
                break
    return indicators


def _check_fingerprinting(commands: list[str]) -> list[EvasionIndicator]:
    indicators: list[EvasionIndicator] = []
    for cmd in commands:
        for pattern, itype in _FINGERPRINT_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                indicators.append(
                    EvasionIndicator(
                        indicator_type=itype,
                        evidence=cmd[:256],
                        confidence=0.7,
                    )
                )
                break
    return indicators


def _check_sandbox_detection(commands: list[str]) -> list[EvasionIndicator]:
    indicators: list[EvasionIndicator] = []
    for cmd in commands:
        for pattern, itype in _SANDBOX_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                indicators.append(
                    EvasionIndicator(
                        indicator_type=itype,
                        evidence=cmd[:256],
                        confidence=0.65,
                    )
                )
                break
    return indicators


def _check_deception_awareness(commands: list[str]) -> list[EvasionIndicator]:
    indicators: list[EvasionIndicator] = []
    for cmd in commands:
        for pattern, itype in _DECEPTION_AWARE_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                indicators.append(
                    EvasionIndicator(
                        indicator_type=itype,
                        evidence=cmd[:256],
                        confidence=0.75,
                    )
                )
                break
    return indicators


def _check_timing_automation(commands: list[str], session_log: dict) -> list[EvasionIndicator]:
    indicators: list[EvasionIndicator] = []
    timestamps: list[float] = []
    for entry in session_log.get("commands", []):
        if isinstance(entry, dict):
            ts = entry.get("timestamp")
            if ts:
                if isinstance(ts, str):
                    try:
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        timestamps.append(dt.timestamp())
                    except ValueError:
                        pass
                elif isinstance(ts, (int, float)):
                    timestamps.append(float(ts))

    if len(timestamps) < _MIN_COMMANDS_FOR_SPEED:
        return indicators

    sorted_ts = sorted(timestamps)
    intervals = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]
    fast_count = sum(1 for iv in intervals if iv < _AUTO_SPEED_THRESHOLD_S)

    if fast_count > 0:
        ratio = fast_count / len(intervals)
        confidence = min(0.95, 0.3 + ratio * 0.65)
        indicators.append(
            EvasionIndicator(
                indicator_type=EvasionIndicatorType.TIMING_ANALYSIS,
                evidence=f"{fast_count}/{len(intervals)} intervals below {_AUTO_SPEED_THRESHOLD_S}s",
                confidence=confidence,
            )
        )

    return indicators


def _calculate_detection_confidence(indicators: list[EvasionIndicator]) -> float:
    if not indicators:
        return 0.0
    combined = 1.0
    for ind in indicators:
        combined *= 1.0 - ind.confidence
    return round(1.0 - combined, 4)


def _build_recommendation(confidence: float, indicators: list[EvasionIndicator]) -> AdjustmentRecommendation | None:
    if confidence < _CUMULATIVE_CONFIDENCE_THRESHOLD:
        return None

    types = {ind.indicator_type for ind in indicators}

    increase_deception = EvasionIndicatorType.DECEPTION_AWARE in types
    reduce_artifacts = confidence > 0.7
    slow_timing = EvasionIndicatorType.TIMING_ANALYSIS in types
    inject_false_flags = EvasionIndicatorType.DECEPTION_AWARE in types or confidence > 0.8
    rotate_persona = confidence > 0.75

    reasons = []
    if increase_deception:
        reasons.append("deception-aware behavior detected")
    if slow_timing:
        reasons.append("automated scanning timing")
    if inject_false_flags:
        reasons.append("high evasion confidence")
    if rotate_persona:
        reasons.append("persona rotation recommended")

    return AdjustmentRecommendation(
        increase_deception=increase_deception,
        reduce_artifacts=reduce_artifacts,
        slow_response_timing=slow_timing,
        inject_false_flags=inject_false_flags,
        persona_rotation=rotate_persona,
        reason="; ".join(reasons) if reasons else "general evasion detected",
    )


class EvasionDetector:
    """Detects when attackers probe for honeypot characteristics."""

    def __init__(self) -> None:
        self._session_history: dict[str, list[EvasionIndicator]] = {}
        logger.info("EvasionDetector initialized")

    def detect(self, session_log: dict) -> EvasionResult:
        session_id = str(session_log.get("session_id", ""))
        commands = _extract_commands(session_log)

        indicators: list[EvasionIndicator] = []
        indicators.extend(_check_tool_signatures(commands))
        indicators.extend(_check_fingerprinting(commands))
        indicators.extend(_check_sandbox_detection(commands))
        indicators.extend(_check_deception_awareness(commands))
        indicators.extend(_check_timing_automation(commands, session_log))

        confidence = _calculate_detection_confidence(indicators)
        detected = confidence >= _DETECTION_CONFIDENCE_THRESHOLD

        history = self._session_history.setdefault(session_id, [])
        history.extend(indicators)
        cumulative = _calculate_detection_confidence(history)

        recommendation = _build_recommendation(cumulative, history)

        result = EvasionResult(
            session_id=session_id,
            detected=detected,
            indicators=indicators,
            detection_confidence=cumulative,
            recommendation=recommendation,
            timestamp=datetime.now(timezone.utc),
        )

        if detected:
            logger.warning(
                "Evasion detected for session %s (confidence=%.3f, indicators=%d)",
                session_id,
                confidence,
                len(indicators),
            )

        return result

    def calculate_detection_confidence(self, indicators: list[EvasionIndicator]) -> float:
        return _calculate_detection_confidence(indicators)

    def recommend_response_adjustment(self, evasion_result: EvasionResult) -> AdjustmentRecommendation:
        if evasion_result.recommendation is not None:
            return evasion_result.recommendation
        return AdjustmentRecommendation(
            increase_deception=False,
            reduce_artifacts=False,
            slow_response_timing=False,
            inject_false_flags=False,
            persona_rotation=False,
            reason="no evasion detected",
        )
