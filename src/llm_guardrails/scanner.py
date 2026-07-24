from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import asdict, dataclass


ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
API_KEY_RE = re.compile(r"\b(?:sk|api|key|token)[-_][A-Za-z0-9_-]{16,}\b", re.IGNORECASE)


@dataclass(frozen=True)
class Detection:
    rule: str
    category: str
    weight: float
    message: str
    start: int = 0
    end: int = 0


@dataclass(frozen=True)
class ScanResult:
    safe: bool
    action: str
    risk_score: float
    normalized_text: str
    detections: tuple[Detection, ...]
    sanitized_text: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


INPUT_RULES = (
    (
        "GRD001", "instruction_override", 0.55,
        re.compile(r"\b(ignore|disregard|forget|override)\b.{0,45}\b(previous|prior|above|system|developer)\b.{0,20}\b(instruction|message|prompt)s?\b", re.I | re.S),
        "Attempts to override higher-priority instructions.",
    ),
    (
        "GRD002", "prompt_exfiltration", 0.6,
        re.compile(r"\b(reveal|show|print|repeat|leak|expose)\b.{0,45}\b(system prompt|hidden instruction|developer message|secret|policy)\b", re.I | re.S),
        "Requests hidden prompts, policy, or secrets.",
    ),
    (
        "GRD003", "role_manipulation", 0.35,
        re.compile(r"\b(you are now|act as|pretend to be|enter)\b.{0,35}\b(unrestricted|developer|system|admin|root|jailbreak|mode)\b", re.I | re.S),
        "Attempts to assign a privileged or unrestricted role.",
    ),
    (
        "GRD004", "tool_abuse", 0.5,
        re.compile(r"\b(run|execute|call|invoke|use)\b.{0,35}\b(shell|terminal|tool|function)\b.{0,50}\b(delete|upload|exfiltrate|send|download|command)\b", re.I | re.S),
        "Attempts to drive a tool toward a high-risk action.",
    ),
    (
        "GRD005", "authority_spoofing", 0.4,
        re.compile(r"(?:^|\n)\s*(system|developer|assistant)\s*:\s*", re.I),
        "Contains a message that imitates a privileged role.",
    ),
)


class GuardrailEngine:
    def __init__(self, review_threshold: float = 0.35, block_threshold: float = 0.7, max_chars: int = 20_000) -> None:
        if not 0 <= review_threshold <= block_threshold <= 1:
            raise ValueError("Thresholds must satisfy 0 <= review <= block <= 1")
        self.review_threshold = review_threshold
        self.block_threshold = block_threshold
        self.max_chars = max_chars

    @staticmethod
    def normalize(text: str) -> str:
        return ZERO_WIDTH_RE.sub("", unicodedata.normalize("NFKC", text)).replace("\x00", "")

    def scan_input(self, text: str) -> ScanResult:
        normalized = self.normalize(text)
        detections: list[Detection] = []
        for rule, category, weight, pattern, message in INPUT_RULES:
            for match in pattern.finditer(normalized):
                detections.append(Detection(rule, category, weight, message, match.start(), match.end()))
        if normalized != text:
            detections.append(Detection(
                "GRD006", "obfuscation", 0.2,
                "Invisible or compatibility characters were normalized.",
            ))
        if len(normalized) > self.max_chars:
            detections.append(Detection(
                "GRD007", "resource_abuse", 0.45,
                f"Input exceeds the {self.max_chars}-character limit.",
            ))
        for match in BASE64_RE.finditer(normalized):
            decoded = self._decode_base64(match.group())
            if decoded and any(pattern.search(decoded) for _, _, _, pattern, _ in INPUT_RULES):
                detections.append(Detection(
                    "GRD008", "encoded_injection", 0.65,
                    "Base64 text decodes to a likely prompt injection.", match.start(), match.end(),
                ))
        risk = self._risk(detections)
        action = "block" if risk >= self.block_threshold else "review" if risk >= self.review_threshold else "allow"
        return ScanResult(
            safe=action == "allow",
            action=action,
            risk_score=risk,
            normalized_text=normalized,
            detections=tuple(detections),
            sanitized_text=normalized[:self.max_chars],
        )

    def scan_output(self, text: str, canary: str | None = None, redact: bool = True) -> ScanResult:
        normalized = self.normalize(text)
        detections: list[Detection] = []
        sanitized = normalized
        patterns = (
            ("GRD101", "email", 0.25, EMAIL_RE, "Output contains an email address.", "[REDACTED_EMAIL]"),
            ("GRD102", "payment_card", 0.7, CARD_RE, "Output may contain a payment card number.", "[REDACTED_CARD]"),
            ("GRD103", "api_key", 0.75, API_KEY_RE, "Output may contain an API key or token.", "[REDACTED_KEY]"),
        )
        for rule, category, weight, pattern, message, replacement in patterns:
            for match in pattern.finditer(normalized):
                detections.append(Detection(rule, category, weight, message, match.start(), match.end()))
            if redact:
                sanitized = pattern.sub(replacement, sanitized)
        if canary and canary in normalized:
            start = normalized.index(canary)
            detections.append(Detection(
                "GRD104", "canary_leak", 1.0,
                "Output leaked the configured private canary.", start, start + len(canary),
            ))
            if redact:
                sanitized = sanitized.replace(canary, "[REDACTED_CANARY]")
        risk = self._risk(detections)
        action = "block" if risk >= self.block_threshold else "review" if risk >= self.review_threshold else "allow"
        return ScanResult(action == "allow", action, risk, normalized, tuple(detections), sanitized)

    @staticmethod
    def _risk(detections: list[Detection]) -> float:
        remaining_safety = 1.0
        for detection in detections:
            remaining_safety *= 1 - detection.weight
        return round(1 - remaining_safety, 4)

    @staticmethod
    def _decode_base64(value: str) -> str:
        try:
            padding = "=" * (-len(value) % 4)
            return base64.b64decode(value + padding, validate=True).decode("utf-8", errors="ignore")
        except (ValueError, UnicodeError):
            return ""

