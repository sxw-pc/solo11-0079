"""Deterministic JSON, Markdown and self-contained HTML report writing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import REPORT_VERSION, __version__
from .disclosure import (
    OPTIMAL,
    DisclosureError,
    DisclosurePolicy,
    ReleaseDecision,
    SearchBudget,
    build_count_table,
    build_release,
)
from .paths import stable_json
from .pipeline import RunBundle
from .timeutil import format_utc

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"

SHARED_ARTIFACT_KIND = "shared_statistics_release"

_GUARANTEE = (
    "Within this fixed table and the declared non-negative integer cell upper "
    "bound, every protected cell admits at least two complete legal table "
    "completions consistent with everything published here, so it cannot be "
    "exactly reconstructed from this artifact alone."
)
_LIMITATIONS = (
    "This certificate is not differential privacy and does not protect against "
    "external knowledge, other releases, slice subtraction outside this fixed "
    "cube, or future runs."
)


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
    }


def build_shared_report(
    bundle: RunBundle,
    policy: DisclosurePolicy,
    budget: SearchBudget | None = None,
) -> dict[str, Any]:
    """Build the frozen shared statistics cube for one authorized contract.

    Raises DisclosureError when the release decision is not a proven optimum:
    an unproven or infeasible candidate table is never published.
    """
    table = build_count_table(bundle.plan, bundle.findings, bundle.backups, bundle.events)
    decision = build_release(table, policy, budget)
    if decision.status != OPTIMAL:
        raise DisclosureError(
            f"shared statistics release '{policy.name}' is not publishable: "
            f"{decision.status} ({decision.detail})"
        )
    return build_shared_artifact(decision, bundle.run_id, format_utc(bundle.plan.as_of))


def build_shared_artifact(
    decision: ReleaseDecision, run_id: str, as_of: str
) -> dict[str, Any]:
    """Freeze one proven-optimal release decision into the shared JSON cube."""
    table = decision.table
    policy = decision.policy
    published = dict(decision.published)
    suppressed = {item.item: item.reason for item in decision.suppressed}

    def entry(item_id: str, keys: dict[str, str], source: dict[str, str]) -> dict[str, Any]:
        if item_id in published:
            return {**keys, "status": "published", "value": published[item_id], "source": source}
        return {**keys, "status": "suppressed", "reason": suppressed[item_id]}

    cube_rows = [
        {"dataset_id": row_id, "owner_team": owner}
        for row_id, owner in zip(table.rows, table.row_owners)
    ]
    cells = [
        entry(
            f"cell:{row_id}/{column}",
            {"row": row_id, "column": column},
            {"kind": "finding_count", "dataset_id": row_id, "severity": column},
        )
        for row_id in table.rows
        for column in table.columns
    ]
    row_totals = [
        entry(f"row_total:{row_id}", {"row": row_id}, {"kind": "row_total", "dataset_id": row_id})
        for row_id in table.rows
    ]
    column_totals = [
        entry(
            f"column_total:{column}",
            {"column": column},
            {"kind": "column_total", "severity": column},
        )
        for column in table.columns
    ]
    grand_total = entry("grand_total", {}, {"kind": "grand_total"})
    return {
        "schema_version": REPORT_VERSION,
        "artifact_kind": SHARED_ARTIFACT_KIND,
        "tool": {"name": "drillverify", "version": __version__},
        "run_id": run_id,
        "generated_at": as_of,
        "as_of": as_of,
        "contract": {
            "name": policy.name,
            "low_count_threshold": policy.low_count_threshold,
            "cell_upper_bound": policy.cell_upper_bound,
            "keep_marginals": policy.keep_marginals,
            "weights": {
                "cell": policy.weights.cell,
                "row_total": policy.weights.row_total,
                "column_total": policy.weights.column_total,
                "grand_total": policy.weights.grand_total,
            },
        },
        "cube": {
            "rows": cube_rows,
            "columns": list(table.columns),
            "cells": cells,
            "row_totals": row_totals,
            "column_totals": column_totals,
            "grand_total": grand_total,
        },
        "certificate": {
            "status": decision.status,
            "proof_method": "exact_branch_and_bound",
            "released_weight": decision.released_weight,
            "available_weight": decision.available_weight,
            "release_nodes": decision.release_nodes,
            "oracle_nodes": decision.oracle_nodes,
            "sensitive_cells": sorted({w.cell for w in decision.witnesses}),
            "witnesses": [
                {"cell": w.cell, "value": w.value, "table": [list(r) for r in w.table]}
                for w in decision.witnesses
            ],
            "guarantee": _GUARANTEE,
            "limitations": _LIMITATIONS,
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


def write_reports(
    bundle: RunBundle,
    out_dir: Path,
    shared_policies: tuple[DisclosurePolicy, ...] = (),
) -> dict[str, Path]:
    """Write all report formats and return a stable path map.

    With no ``shared_policies`` this writes exactly the classic full internal
    report set. Each listed contract adds one frozen shared statistics cube;
    a contract whose release decision is not a proven optimum raises
    DisclosureError and no candidate table is written.
    """
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
    for policy in shared_policies:
        artifact = build_shared_report(bundle, policy)
        path = out_dir / f"shared_report_{policy.name}.json"
        _dump_json(path, artifact)
        outputs[f"shared:{policy.name}"] = path
    return outputs
