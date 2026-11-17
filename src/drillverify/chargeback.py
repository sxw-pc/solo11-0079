"""Optional physical block inventory verification and storage chargeback.

A declared block inventory is verified like any other evidence: reference
ranges, block object fingerprints and per-artifact logical coverage must match,
and a repeated block_id must declare identical physical content (same name or
same SHA alone never implies store-side dedup). Any conflict or missing block
leaves the bill unproven; nothing is silently counted as zero. Verified usage
is billed per period (UTC month of backup finish) and tier, counting each
physical block once, priced with exact decimal tiered rates plus a configurable
minimum fee. Two pre-authorized contracts settle the same proven total:
``primary_owner`` (each block's tiered marginal cost, in fixed block_id order,
goes to its inventory-designated primary team) and ``shapley`` (exact average
marginal contribution over all join orders, within authorized team/subset
limits). Both are budget-balanced, non-negative and traceable to blocks and
teams. Recovery conclusions (artifact readiness, chains, RPO, retention) are
never affected; billing findings stay inside this section.
"""
from __future__ import annotations
import json
import re
from decimal import Decimal
from fractions import Fraction
from itertools import combinations
from math import factorial
from pathlib import Path
from typing import Any
from .models import ChargebackConfig, FileFingerprint, Finding, RecoveryPlan, TierPricing
from .paths import UnsafePath, resolve_under, safe_relative, sha256_file
from .records import BackupRecord, BlockRef, StorageAssessment, StorageBlock, StorageInventory
from .results import BucketBill, ChargebackReport, ContractSettlement, TeamCharge, format_amount, format_decimal
MB_BYTES = Decimal(1_000_000)
_BLOCK_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")
def _parse_block(entry: object) -> StorageBlock | None:
    if not isinstance(entry, dict):
        return None
    block_id, digest, size = entry.get("block_id"), entry.get("sha256"), entry.get("size_bytes")
    tier, path, team = entry.get("tier"), entry.get("object_path"), entry.get("primary_team")
    if not (isinstance(block_id, str) and _BLOCK_RE.fullmatch(block_id)):
        return None
    if not (isinstance(digest, str) and _SHA_RE.fullmatch(digest)):
        return None
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        return None
    if not (isinstance(tier, str) and _BLOCK_RE.fullmatch(tier)):
        return None
    if not (isinstance(path, str) and path.strip() and isinstance(team, str) and team.strip()):
        return None
    return StorageBlock(block_id, digest.lower(), size, tier, path.strip(), team.strip())
def _parse_refs(entries: object, verified: dict[str, StorageBlock]) -> tuple[BlockRef, ...] | None:
    if not isinstance(entries, list):
        return None
    parsed: list[BlockRef] = []
    for entry in entries:
        if not isinstance(entry, dict):
            return None
        block_id, offset, length = entry.get("block_id"), entry.get("offset_bytes"), entry.get("length_bytes")
        block = verified.get(block_id) if isinstance(block_id, str) else None
        if block is None or any(isinstance(v, bool) or not isinstance(v, int) for v in (offset, length)):
            return None
        if offset < 0 or length < 1 or length > block.size_bytes:
            return None
        parsed.append(BlockRef(block_id, offset, length))
    return tuple(parsed)
def _storage_result(inventory, findings, files) -> StorageAssessment:
    unique = {item.path: item for item in files}
    return StorageAssessment(
        inventory if not findings else None,
        tuple(sorted(findings, key=Finding.sort_key)),
        tuple(sorted(unique.values(), key=lambda item: item.path)),
    )
def assess_storage(
    backups: tuple[BackupRecord, ...],
    ready_ids: set[str],
    config: ChargebackConfig | None,
    fixtures_root: Path,
) -> StorageAssessment:
    """Verify the declared block inventory; any defect leaves the bill unproven."""
    if config is None:
        return StorageAssessment(None, (), ())
    root = fixtures_root.resolve()
    try:
        path = resolve_under(root, config.inventory_path, field="inventory_path")
        rel = safe_relative(root, path)
    except UnsafePath as exc:
        finding = Finding("BILL-001", "high", "input", "block_inventory", str(exc), config.inventory_path)
        return StorageAssessment(None, (finding,), ())
    if not path.is_file():
        finding = Finding("BILL-001", "high", "input", rel, "Declared block inventory is missing.", rel)
        return StorageAssessment(None, (finding,), ())
    file_hash = sha256_file(path)
    files = [FileFingerprint(rel, file_hash, path.stat().st_size)]
    findings: list[Finding] = []
    def issue(rule: str, object_id: str, message: str, **evidence: Any) -> None:
        findings.append(Finding(rule, "high", "storage_block", object_id, message, rel, 0, evidence, file_hash))
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raw = None
    if not isinstance(raw, dict) or not isinstance(raw.get("blocks"), list) or not isinstance(raw.get("artifacts"), dict):
        issue("BILL-001", rel, "Block inventory must be a JSON object with 'blocks' and 'artifacts'.")
        return _storage_result(None, findings, files)
    declared: dict[str, StorageBlock] = {}
    conflicts: set[str] = set()
    for entry in raw["blocks"]:
        block = _parse_block(entry)
        if block is None:
            issue("BILL-002", str(entry.get("block_id")) if isinstance(entry, dict) else "block", "Block declaration is invalid.")
            continue
        if block.block_id in conflicts:
            continue
        prior = declared.get(block.block_id)
        if prior is None:
            declared[block.block_id] = block
        elif prior != block:
            conflicts.add(block.block_id)
            declared.pop(block.block_id)
    for block_id in sorted(conflicts):
        issue("BILL-003", block_id, "block_id is redeclared with conflicting physical attributes.")
    verified: dict[str, StorageBlock] = {}
    for block_id in sorted(declared):
        block = declared[block_id]
        try:
            obj = resolve_under(root, block.object_path, field="object_path")
        except UnsafePath as exc:
            issue("BILL-002", block_id, str(exc))
            continue
        if not obj.is_file():
            issue("BILL-004", block_id, "Block object file is missing.", object_path=block.object_path)
            continue
        digest, size = sha256_file(obj), obj.stat().st_size
        files.append(FileFingerprint(safe_relative(root, obj), digest, size))
        if size != block.size_bytes or digest != block.sha256:
            issue("BILL-005", block_id, "Block object fingerprint does not match the inventory.",
                  expected_sha256=block.sha256, actual_sha256=digest, expected_size=block.size_bytes, actual_size=size)
            continue
        verified[block_id] = block
    catalog = {item.backup_id: item for item in backups}
    refs: dict[str, tuple[BlockRef, ...]] = {}
    for backup_id in sorted(raw["artifacts"]):
        backup = catalog.get(backup_id)
        parsed = _parse_refs(raw["artifacts"][backup_id], verified)
        if backup is None:
            issue("BILL-006", str(backup_id), "Block references name an unknown backup.")
            continue
        if parsed is None:
            issue("BILL-006", backup_id, "Block references are invalid or name unverified blocks.")
            continue
        covered, ordered = 0, True
        for ref in parsed:
            ordered = ordered and ref.offset_bytes == covered
            covered += ref.length_bytes
        if not ordered or covered != backup.artifact_size_bytes:
            issue("BILL-006", backup_id, "Block references do not cover the catalogued bytes in order.",
                  expected=backup.artifact_size_bytes, covered=covered)
        else:
            refs[backup_id] = parsed
    for backup_id in sorted(ready_ids - refs.keys()):
        issue("BILL-006", backup_id, "Verified artifact has no block references; physical usage is unproven.")
    inventory = StorageInventory(tuple(verified[b] for b in sorted(verified)), refs)
    return _storage_result(inventory, findings, files)
def tiered_cost(size_bytes: int, pricing: TierPricing) -> Decimal:
    """Exact decimal ladder cost; 1 MB = 1_000_000 bytes, fractional MB billed."""
    remaining = Decimal(size_bytes) / MB_BYTES
    cost = Decimal(0)
    for step in pricing.steps:
        if remaining <= 0:
            break
        take = remaining if step.up_to_mb is None else min(remaining, step.up_to_mb)
        cost += take * step.per_mb
        remaining -= take
    return cost
def invoice_for(size_bytes: int, pricing: TierPricing) -> Decimal:
    """Bill one period/tier bucket: empty is free, otherwise the minimum fee applies."""
    if size_bytes <= 0:
        return Decimal(0)
    return max(pricing.min_fee, tiered_cost(size_bytes, pricing))
def _pricing_for(config: ChargebackConfig, tier: str) -> TierPricing:
    return config.pricing.get(tier, config.pricing["default"])
def _settlement(contract, charges, witnesses, usage) -> ContractSettlement:
    names = sorted(set(charges) | {t for teams in usage.values() for team_set in teams.values() for t in team_set})
    teams = tuple(TeamCharge(n, charges.get(n, Fraction(0)), tuple(witnesses.get(n, ()))) for n in names)
    total = sum((c.amount for c in teams), Fraction(0))
    return ContractSettlement(contract, "settled", None, total, teams)
def _settle_primary_owner(config, buckets, blocks, usage) -> ContractSettlement:
    charges: dict[str, Fraction] = {}
    witnesses: dict[str, list[dict[str, Any]]] = {}
    for bucket in buckets:
        pricing, cumulative = _pricing_for(config, bucket.tier), 0
        for block_id in bucket.block_ids:
            block = blocks[block_id]
            before = invoice_for(cumulative, pricing)
            cumulative += block.size_bytes
            marginal = invoice_for(cumulative, pricing) - before
            team = block.primary_team
            charges[team] = charges.get(team, Fraction(0)) + Fraction(marginal)
            witnesses.setdefault(team, []).append({
                "kind": "block_marginal", "period": bucket.period, "tier": bucket.tier,
                "block_id": block_id, "block_bytes": block.size_bytes,
                "cumulative_bytes_before": cumulative - block.size_bytes,
                "users": sorted(usage[(bucket.period, bucket.tier)][block_id]),
                "marginal": format_decimal(marginal)})
    return _settlement("primary_owner", charges, witnesses, usage)
def _settle_shapley(config, buckets, blocks, usage) -> ContractSettlement:
    charges: dict[str, Fraction] = {}
    witnesses: dict[str, list[dict[str, Any]]] = {}
    for bucket in buckets:
        key = (bucket.period, bucket.tier)
        members = sorted({t for team_set in usage[key].values() for t in team_set})
        n = len(members)
        if n == 0:
            continue
        if n > config.max_teams or 2 ** n > config.max_subsets:
            reason = (f"shapley needs {n} teams ({2 ** n} subsets) in {bucket.period}/{bucket.tier}, "
                      f"beyond authorized limits (max_teams={config.max_teams}, max_subsets={config.max_subsets})")
            return ContractSettlement("shapley", "unavailable", reason, None, ())
        pricing = _pricing_for(config, bucket.tier)
        team_blocks = {t: {b for b, ts in usage[key].items() if t in ts} for t in members}
        cost: dict[frozenset, Fraction] = {}
        for size in range(n + 1):
            for combo in combinations(members, size):
                used = set().union(*(team_blocks[t] for t in combo)) if combo else set()
                cost[frozenset(combo)] = Fraction(invoice_for(sum(blocks[b].size_bytes for b in used), pricing))
        facts = [factorial(i) for i in range(n + 1)]
        for team in members:
            others = [t for t in members if t != team]
            total = Fraction(0)
            for size in range(len(others) + 1):
                weight = Fraction(facts[size] * facts[n - 1 - size], facts[n])
                for combo in combinations(others, size):
                    prior = set().union(*(team_blocks[t] for t in combo)) if combo else set()
                    marginal = cost[frozenset((*combo, team))] - cost[frozenset(combo)]
                    total += weight * marginal
                    witnesses.setdefault(team, []).append({
                        "kind": "shapley_marginal", "period": bucket.period, "tier": bucket.tier,
                        "subset": list(combo), "weight": format_amount(weight),
                        "blocks_added": sorted(team_blocks[team] - prior),
                        "marginal": format_amount(marginal)})
            charges[team] = charges.get(team, Fraction(0)) + total
    return _settlement("shapley", charges, witnesses, usage)
def build_chargeback(
    plan: RecoveryPlan,
    backups: tuple[BackupRecord, ...],
    ready_ids: set[str],
    config: ChargebackConfig | None,
    storage: StorageAssessment,
    config_findings: tuple[Finding, ...],
) -> ChargebackReport:
    """Settle the optional storage bill; recovery conclusions are never inputs."""
    owners = {item.dataset_id: item.owner_team for item in plan.datasets}
    team_logical: dict[str, int] = {}
    for backup in backups:
        team = owners.get(backup.dataset_id, "unassigned")
        team_logical[team] = team_logical.get(team, 0) + backup.artifact_size_bytes
    logical_rows = tuple(sorted(team_logical.items()))
    logical_bytes = sum(team_logical.values())
    if config is None:
        status = "unproven" if config_findings else "not_configured"
        return ChargebackReport(status, config_findings, logical_bytes, logical_rows, None, None, (), "units")
    findings = tuple(sorted(config_findings + storage.findings, key=Finding.sort_key))
    if findings or storage.inventory is None:
        return ChargebackReport("unproven", findings, logical_bytes, logical_rows, None, None, (), config.currency, config)
    blocks = {block.block_id: block for block in storage.inventory.blocks}
    usage: dict[tuple[str, str], dict[str, set[str]]] = {}
    for backup in backups:
        if backup.backup_id not in ready_ids:
            continue
        period, team = backup.finished_at.strftime("%Y-%m"), owners.get(backup.dataset_id, "unassigned")
        for ref in storage.inventory.refs.get(backup.backup_id, ()):
            block = blocks[ref.block_id]
            usage.setdefault((period, block.tier), {}).setdefault(ref.block_id, set()).add(team)
    buckets = tuple(
        BucketBill(period, tier, tuple(sorted(members)),
                   union := sum(blocks[b].size_bytes for b in members),
                   invoice_for(union, _pricing_for(config, tier)))
        for (period, tier), members in sorted(usage.items())
    )
    total = sum((bucket.invoice for bucket in buckets), Decimal(0))
    contracts = [_settle_primary_owner(config, buckets, blocks, usage), _settle_shapley(config, buckets, blocks, usage)]
    extra: tuple[Finding, ...] = ()
    if contracts[1].status != "settled":
        extra = (Finding("BILL-008", "warning", "chargeback", "shapley",
                         contracts[1].reason or "shapley limits exceeded", config.inventory_path),)
    checked = []
    for contract in contracts:
        broken = contract.status == "settled" and (
            contract.total != Fraction(total) or any(c.amount < 0 for c in contract.teams))
        checked.append(contract if not broken else
                       ContractSettlement(contract.contract, "unavailable", "internal budget check failed", None, ()))
    return ChargebackReport("settled", findings + extra, logical_bytes, logical_rows,
                            buckets, total, tuple(checked), config.currency, config)
