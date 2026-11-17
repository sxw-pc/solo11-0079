"""Artifact, manifest and drill-evidence integrity checks."""
from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path
from .models import FileFingerprint, Finding
from .paths import UnsafePath, resolve_under, sha256_file
from .records import DrillEvent, EvidenceCheck
from .artifact_review import ArtifactAssessment, assess_artifacts
__all__ = [
    "ArtifactAssessment",
    "EvidenceAssessment",
    "assess_artifacts",
    "assess_evidence",
]
@dataclass(frozen=True)
class EvidenceAssessment:
    checks: tuple[EvidenceCheck, ...]
    findings: tuple[Finding, ...]
    files: tuple[FileFingerprint, ...]
    def ok_refs(self) -> set[str]:
        return {item.evidence_ref for item in self.checks if item.valid}
def assess_evidence(
    events: tuple[DrillEvent, ...],
    fixtures_root: Path,
) -> EvidenceAssessment:
    """Verify every distinct evidence reference once."""
    root = fixtures_root.resolve()
    refs: dict[str, int] = {}
    for event in events:
        refs.setdefault(event.evidence_ref, event.line_no)
    checks: list[EvidenceCheck] = []
    findings: list[Finding] = []
    files: list[FileFingerprint] = []
    for ref in sorted(refs):
        try:
            path = resolve_under(root, ref, field="evidence_ref")
        except UnsafePath as exc:
            checks.append(EvidenceCheck(ref, False, False, False, "", 0))
            findings.append(Finding("EVID-002", "high", "evidence", ref, str(exc), ref, refs[ref]))
            continue
        if not path.is_file():
            checks.append(EvidenceCheck(ref, False, False, False, "", 0))
            findings.append(
                Finding(
                    "EVID-001",
                    "high",
                    "evidence",
                    ref,
                    "Referenced evidence file does not exist.",
                    ref,
                    refs[ref],
                )
            )
            continue
        try:
            payload = path.read_bytes()
        except OSError:
            checks.append(EvidenceCheck(ref, True, False, False, "", 0))
            findings.append(
                Finding(
                    "EVID-002", "high", "evidence", ref,
                    "Evidence file is unreadable.", ref, refs[ref],
                )
            )
            continue
        digest = sha256_file(path)
        valid = bool(payload.strip())
        detail = "Evidence file is empty."
        if valid and path.suffix.lower() == ".json":
            try:
                document = json.loads(payload.decode("utf-8"))
                valid = isinstance(document, dict) and isinstance(document.get("evidence_id"), str)
                detail = "JSON evidence must be an object with a string evidence_id."
            except (UnicodeError, json.JSONDecodeError):
                valid = False
                detail = "JSON evidence cannot be parsed."
        checks.append(EvidenceCheck(ref, True, True, valid, digest, len(payload)))
        files.append(FileFingerprint(ref, digest, len(payload)))
        if not valid:
            findings.append(
                Finding(
                    "EVID-002",
                    "high",
                    "evidence",
                    ref,
                    detail,
                    ref,
                    refs[ref],
                    {"size_bytes": len(payload)},
                    digest,
                )
            )
    return EvidenceAssessment(
        tuple(checks),
        tuple(sorted(findings, key=Finding.sort_key)),
        tuple(sorted(files, key=lambda item: item.path)),
    )
