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
        "chargeback": bundle.chargeback.to_dict(),
        "remediation_plan": {
            "summary": bundle.plan_summary,
            "actions": [item.to_dict() for item in bundle.actions],
        },
    }


def _dump_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


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
    chargeback = report["chargeback"]
    if chargeback["status"] != "not_configured":
        lines.extend(["", "## Storage Chargeback", ""])
        lines.append(f"- Status: **{chargeback['status']}**")
        lines.append(f"- Logical bytes (catalog sum; shared blocks are double-counted here): `{chargeback['logical_bytes']}`")
        physical = chargeback["physical"]
        if physical is not None:
            lines.append(f"- Total invoice: `{physical['total_invoice']}` {chargeback['currency']}")
            lines.extend(["", "| Period | Tier | Blocks | Union bytes | Invoice |", "|---|---|---:|---:|---:|"])
            for bucket in physical["buckets"]:
                lines.append(
                    f"| {bucket['period']} | {bucket['tier']} | {len(bucket['block_ids'])} | "
                    f"{bucket['union_bytes']} | {bucket['invoice']} |"
                )
            for contract in chargeback["contracts"]:
                lines.extend(["", f"### Contract `{contract['contract']}`", ""])
                if contract["status"] != "settled":
                    lines.append(f"_Unavailable: {contract['reason']}_")
                    continue
                lines.append(f"Budget balanced: `{contract['budget_balanced']}`; total `{contract['total']}`.")
                lines.extend(["", "| Team | Amount |", "|---|---:|"])
                for charge in contract["teams"]:
                    lines.append(f"| {_cell(charge['team'])} | {charge['amount']} |")
        if chargeback["findings"]:
            lines.extend(["", "| Rule | Object | Message |", "|---|---|---|"])
            for item in chargeback["findings"]:
                lines.append(f"| {item['rule_id']} | {_cell(item['object_id'])} | {_cell(item['message'])} |")
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
