"""Deterministic JSON, Markdown and self-contained HTML report writing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import REPORT_VERSION, __version__
from .paths import stable_json
from .pipeline import RunBundle
from .timeutil import format_utc

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"


def build_report(bundle: RunBundle) -> dict[str, Any]:
    """Assemble the complete, deterministic report document."""
    plan = bundle.plan
    return {
        "schema_version": REPORT_VERSION,
        "tool": {"name": "drillverify", "version": __version__},
        "run_id": bundle.run_id,
        "generated_at": format_utc(plan.as_of),
        "as_of": format_utc(plan.as_of),
        "window_start": format_utc(plan.window_start),
        "status": bundle.status,
        "summary": bundle.summary,
        "plan": plan.to_dict(),
        "input_manifest": [item.to_dict() for item in bundle.inputs],
        "datasets": list(bundle.dataset_summaries),
        "backups": [item.to_dict() for item in bundle.backups],
        "chains": [item.to_dict() for item in bundle.chains],
        "restorable_points": [item.to_dict() for item in bundle.points],
        "objectives": {
            "rpo": [item.to_dict() for item in bundle.rpo],
            "rto": [item.to_dict() for item in bundle.rto],
        },
        "drills": [item.to_dict() for item in bundle.drills],
        "artifacts": [item.to_dict() for item in bundle.artifacts],
        "evidence": [item.to_dict() for item in bundle.evidence],
        "findings": [item.to_dict() for item in bundle.findings],
        "attribution": {
            "summary": bundle.attribution_summary,
            "records": [item.to_dict() for item in bundle.attribution],
        },
        "remediation_plan": {
            "summary": bundle.plan_summary,
            "actions": [item.to_dict() for item in bundle.actions],
        },
        "closure_review": bundle.closures,
    }


def _dump_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _render_closure_markdown(review: dict[str, Any]) -> list[str]:
    lines = ["", "## Closure Review", ""]
    summary = review["summary"]
    lines.append(
        f"- Approval book: `{review['availability']}`; closed: {summary['closed']}; "
        f"pending re-approval: {summary['pending_reapproval']}; reopened: {summary['reopened']}; "
        f"unproven: {summary['unproven']}; open: {summary['open']}."
    )
    lines.append(
        "- This section records whether the remediation *process* may be closed. "
        "It does not assert that technical recovery succeeded and does not change "
        "backup chains, RPO/RTO results or action due dates."
    )
    if review["availability"] == "no_approval_book":
        lines.append("- No approval book was supplied; every action keeps its original plan view.")
        return lines
    lines.extend(["", "| Action | Status | Evidence version | Declarers / approvers | Witness |", "|---|---|---|---|---|"])
    for decision in review["decisions"]:
        evidence = decision["evidence"] or {}
        approvers = ", ".join(
            f"{item['display_name']} ({item['role_label']}, {item['authorization']})"
            for item in decision["approvers"]
        ) or "none"
        witness = "; ".join(f"{item['code']} @ {item['source'] or 'n/a'}" for item in decision["witness"]) or "none"
        lines.append(
            f"| `{decision['action_id']}` | {decision['status']} | {evidence.get('version', 'n/a')} | "
            f"{_cell(approvers)} | {_cell(witness)} |"
        )
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# DrillVerify Verification Report",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Status: **{report['status'].upper()}**",
        f"- As of: `{report['as_of']}`",
        f"- Analysis window start: `{report['window_start']}`",
        "- Time basis: configured `as_of` only (no runtime clock)",
        "",
        "## Summary",
        "",
    ]
    for key in sorted(report["summary"]):
        value = report["summary"][key]
        lines.append(
            f"- {key}: `{json.dumps(value, sort_keys=True)}`"
            if isinstance(value, dict)
            else f"- {key}: `{value}`"
        )
    lines.extend(["", "## Datasets", "", "| Dataset | Status | Points | RPO status | Max gap | Drills |", "|---|---|---:|---|---:|---:|"])
    for item in report["datasets"]:
        lines.append(
            f"| {_cell(item['dataset_id'])} | {item['status']} | {item['point_count']} | "
            f"{item['rpo']['status']} | {item['rpo']['max_gap_minutes']} | {item['drill_count']} |"
        )
    lines.extend(["", "## Sample Findings", "", "| Severity | Rule | Object | Message |", "|---|---|---|---|"])
    for item in report["findings"][:40]:
        lines.append(
            f"| {item['severity']} | {item['rule_id']} | {_cell(item['object_id'])} | {_cell(item['message'])} |"
        )
    if len(report["findings"]) > 40:
        lines.append(f"|  |  |  | _and {len(report['findings']) - 40} more in report.json_ |")
    lines.extend(["", "## Remediation Plan", "", "| Priority | Owner | Rule(s) | Object | Due | Action |", "|---|---|---|---|---|---|"])
    for action in report["remediation_plan"]["actions"]:
        lines.append(
            f"| {action['priority']} | {_cell(action['owner_team'])} | {_cell(', '.join(action['rule_ids']))} | "
            f"{_cell(action['object_id'])} | {action['due_at']} | {_cell(action['title'])} |"
        )
    lines.extend(_render_closure_markdown(report["closure_review"]))
    lines.extend(
        [
            "",
            "## Input Manifest",
            "",
            "| File | SHA-256 | Bytes |",
            "|---|---|---:|",
        ]
    )
    for item in report["input_manifest"]:
        lines.append(f"| {_cell(item['path'])} | `{item['sha256']}` | {item['size_bytes']} |")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A failed drill is evidence about the recovery procedure, not proof that the source data is lost. "
            "Every conclusion above is tied to a rule ID, object ID, file line and input SHA-256.",
            "",
        ]
    )
    return "\n".join(lines)


def render_html(report: dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.html")
    css = (STATIC_DIR / "app.css").read_text(encoding="utf-8")
    return template.render(report=report, css=css)


def write_reports(bundle: RunBundle, out_dir: Path) -> dict[str, Path]:
    """Write all report formats and return a stable path map."""
    out_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(bundle)
    outputs: dict[str, Path] = {
        "json": out_dir / "report.json",
        "markdown": out_dir / "report.md",
        "html": out_dir / "report.html",
        "plan": out_dir / "remediation_plan.json",
        "manifest": out_dir / "run_manifest.json",
    }
    _dump_json(outputs["json"], report)
    outputs["markdown"].write_text(render_markdown(report), encoding="utf-8")
    outputs["html"].write_text(render_html(report), encoding="utf-8")
    _dump_json(
        outputs["plan"],
        {
            "schema_version": REPORT_VERSION,
            "run_id": bundle.run_id,
            "as_of": format_utc(bundle.plan.as_of),
            "summary": bundle.plan_summary,
            "actions": [item.to_dict() for item in bundle.actions],
        },
    )
    _dump_json(
        outputs["manifest"],
        {
            "schema_version": REPORT_VERSION,
            "tool": {"name": "drillverify", "version": __version__},
            "run_id": bundle.run_id,
            "as_of": format_utc(bundle.plan.as_of),
            "status": bundle.status,
            "deterministic_seed": stable_json(
                [item.to_dict() for item in bundle.inputs]
            ),
            "inputs": [item.to_dict() for item in bundle.inputs],
        },
    )
    return outputs
