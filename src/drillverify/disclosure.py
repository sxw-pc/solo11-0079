"""Exact cell-suppression release decisions for shared audit statistics.

The full local report and the read-only review console remain the authorized
channel for finding-level detail. This module decides which cells and
marginals of a small ``dataset/owner_team x severity`` count table may leave
the bench inside a *shared statistics release* so that every policy-protected
(low-count) cell keeps at least two complete, legal table completions under
the published equations and the declared non-negative integer cell bounds.

Scope of the guarantee: exact-reconstruction resistance for one fixed table
under one declared bound, proven by exhaustive branch-and-bound with two
witness completions per protected cell. This is not differential privacy and
says nothing about external knowledge, other releases, or future runs.
"""

from __future__ import annotations

from dataclasses import dataclass

from .disclosure_solver import BudgetExceeded, SearchBudget, TableOracle
from .models import Finding, RecoveryPlan
from .planner import dataset_owner
from .records import BackupRecord, DrillEvent
from .rules import SEVERITY_RANK

UNASSIGNED_ROW = "(unassigned)"
UNASSIGNED_OWNER = "unassigned"

OPTIMAL = "optimal"
INFEASIBLE = "infeasible"
UNPROVEN = "unproven"

PRIMARY_SENSITIVE = "primary_sensitive"
COMPLEMENTARY_SUPPRESSION = "complementary_suppression"
SUPPRESSION_REASONS = frozenset({PRIMARY_SENSITIVE, COMPLEMENTARY_SUPPRESSION})


class DisclosureError(RuntimeError):
    """Raised when a shared statistics release cannot be certified."""


@dataclass(frozen=True)
class CountTable:
    """Small non-negative integer table: dataset/owner rows x severity columns."""

    rows: tuple[str, ...]
    row_owners: tuple[str, ...]
    columns: tuple[str, ...]
    values: tuple[tuple[int, ...], ...]

    def row_total(self, i: int) -> int:
        return sum(self.values[i])

    def column_total(self, j: int) -> int:
        return sum(row[j] for row in self.values)

    def grand_total(self) -> int:
        return sum(self.row_total(i) for i in range(len(self.rows)))


def build_count_table(
    plan: RecoveryPlan,
    findings: tuple[Finding, ...],
    backups: tuple[BackupRecord, ...],
    events: tuple[DrillEvent, ...],
) -> CountTable:
    """Count findings per dataset/owner x severity using plan owner mapping."""
    owners = {dataset.dataset_id: dataset.owner_team for dataset in plan.datasets}
    backup_owner = {item.backup_id: item.dataset_id for item in backups}
    drill_owner = {item.drill_id: item.dataset_id for item in events}
    severities = sorted(
        {item.severity for item in findings},
        key=lambda name: (SEVERITY_RANK.get(name, 99), name),
    )
    rows = [dataset.dataset_id for dataset in plan.datasets]
    row_owners = [owners[dataset_id] for dataset_id in rows]
    counts: dict[tuple[str, str], int] = {}
    unassigned = False
    for finding in findings:
        dataset_id, _ = dataset_owner(finding, owners, backup_owner, drill_owner)
        row = dataset_id if dataset_id else UNASSIGNED_ROW
        unassigned = unassigned or not dataset_id
        counts[(row, finding.severity)] = counts.get((row, finding.severity), 0) + 1
    if unassigned:
        rows.append(UNASSIGNED_ROW)
        row_owners.append(UNASSIGNED_OWNER)
    values = tuple(
        tuple(counts.get((row, column), 0) for column in severities) for row in rows
    )
    return CountTable(tuple(rows), tuple(row_owners), tuple(severities), values)


@dataclass(frozen=True)
class ReleaseWeights:
    """Publication weight per cube item kind; the optimizer maximizes the sum."""

    cell: int
    row_total: int
    column_total: int
    grand_total: int


@dataclass(frozen=True)
class DisclosurePolicy:
    """One authorized release purpose: sensitivity rule, bounds and weights."""

    name: str
    low_count_threshold: int
    cell_upper_bound: int
    weights: ReleaseWeights
    keep_marginals: bool

    def bound_for(self, sensitive: bool) -> int:
        if sensitive:
            return min(self.cell_upper_bound, self.low_count_threshold)
        return self.cell_upper_bound


def totals_priority_contract(
    *, low_count_threshold: int = 2, cell_upper_bound: int = 50
) -> DisclosurePolicy:
    """Keep every prescribed row/column/grand total; suppress cells as needed."""
    return DisclosurePolicy(
        name="totals_priority",
        low_count_threshold=low_count_threshold,
        cell_upper_bound=cell_upper_bound,
        weights=ReleaseWeights(cell=1, row_total=1, column_total=1, grand_total=1),
        keep_marginals=True,
    )


def detail_priority_contract(
    *, low_count_threshold: int = 2, cell_upper_bound: int = 50
) -> DisclosurePolicy:
    """Prefer non-sensitive detail cells; marginals may be hidden instead."""
    return DisclosurePolicy(
        name="remediation_detail_priority",
        low_count_threshold=low_count_threshold,
        cell_upper_bound=cell_upper_bound,
        weights=ReleaseWeights(cell=6, row_total=2, column_total=2, grand_total=1),
        keep_marginals=False,
    )


@dataclass(frozen=True)
class SuppressedItem:
    item: str
    reason: str


@dataclass(frozen=True)
class CompletionWitness:
    """One complete legal table completion giving ``cell`` a distinct value."""

    cell: str
    value: int
    table: tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class ReleaseDecision:
    """Outcome of one release decision; only OPTIMAL decisions are publishable."""

    status: str
    table: CountTable
    policy: DisclosurePolicy
    published: tuple[tuple[str, int], ...]
    suppressed: tuple[SuppressedItem, ...]
    witnesses: tuple[CompletionWitness, ...]
    released_weight: int
    available_weight: int
    release_nodes: int
    oracle_nodes: int
    detail: str


def _item_id(item: tuple, table: CountTable) -> str:
    if item[0] == "cell":
        return f"cell:{table.rows[item[1]]}/{table.columns[item[2]]}"
    if item[0] == "row":
        return f"row_total:{table.rows[item[1]]}"
    if item[0] == "col":
        return f"column_total:{table.columns[item[1]]}"
    return "grand_total"


def build_release(
    table: CountTable, policy: DisclosurePolicy, budget: SearchBudget | None = None
) -> ReleaseDecision:
    """Choose a maximum-weight publishable set with per-cell safety witnesses."""
    budget = budget if budget is not None else SearchBudget()
    rows, cols = len(table.rows), len(table.columns)
    if policy.low_count_threshold < 0 or policy.cell_upper_bound < 0:
        raise ValueError("policy threshold and cell upper bound must be non-negative")
    weights = policy.weights
    if min(weights.cell, weights.row_total, weights.column_total, weights.grand_total) < 0:
        raise ValueError("policy weights must be non-negative")
    sensitive = frozenset(
        (i, j)
        for i in range(rows)
        for j in range(cols)
        if 0 < table.values[i][j] <= policy.low_count_threshold
    )
    bounds = tuple(
        policy.bound_for((i, j) in sensitive) for i in range(rows) for j in range(cols)
    )
    for i in range(rows):
        for j in range(cols):
            if table.values[i][j] > bounds[i * cols + j]:
                raise ValueError(
                    "declared cell upper bound is below the true count at "
                    f"{table.rows[i]}/{table.columns[j]}"
                )

    def weight_of(item: tuple) -> int:
        return {
            "cell": weights.cell,
            "row": weights.row_total,
            "col": weights.column_total,
            "grand": weights.grand_total,
        }[item[0]]

    marginals = (
        [("row", i) for i in range(rows)]
        + [("col", j) for j in range(cols)]
        + [("grand",)]
    )
    cells = [("cell", i, j) for i in range(rows) for j in range(cols)]
    publishable_cells = [item for item in cells if (item[1], item[2]) not in sensitive]
    if policy.keep_marginals:
        mandatory, optional = marginals, publishable_cells
    else:
        mandatory, optional = [], marginals + publishable_cells
    sensitive_rows = {i for i, _ in sensitive}
    sensitive_cols = {j for _, j in sensitive}

    def near_sensitive(item: tuple) -> bool:
        if item[0] == "grand":
            return True
        if item[0] == "row":
            return item[1] in sensitive_rows
        if item[0] == "col":
            return item[1] in sensitive_cols
        return item[1] in sensitive_rows or item[2] in sensitive_cols

    optional.sort(
        key=lambda item: (-weight_of(item), 0 if near_sensitive(item) else 1, _item_id(item, table))
    )
    suffix = [0] * (len(optional) + 1)
    for k in range(len(optional) - 1, -1, -1):
        suffix[k] = suffix[k + 1] + weight_of(optional[k])
    base = frozenset(mandatory)
    base_weight = sum(weight_of(item) for item in mandatory)
    oracle = TableOracle(rows, cols, table.values, bounds, budget)

    def closed(status: str, detail: str) -> ReleaseDecision:
        return ReleaseDecision(
            status=status,
            table=table,
            policy=policy,
            published=(),
            suppressed=(),
            witnesses=(),
            released_weight=0,
            available_weight=0,
            release_nodes=budget.release_nodes,
            oracle_nodes=budget.oracle_nodes,
            detail=detail,
        )

    best_set: frozenset | None = None
    best_weight = -1
    try:
        if not oracle.is_safe(base, sensitive):
            return closed(
                INFEASIBLE,
                "mandatory marginals pin a protected cell under the declared bounds",
            )

        def recurse(k: int, published: frozenset, weight: int) -> None:
            nonlocal best_set, best_weight
            budget.tick_release()
            if weight + suffix[k] <= best_weight:
                return
            if k == len(optional):
                if weight > best_weight:
                    best_weight = weight
                    best_set = published
                return
            item = optional[k]
            candidate = published | {item}
            if oracle.is_safe(candidate, sensitive):
                recurse(k + 1, candidate, weight + weight_of(item))
            recurse(k + 1, published, weight)

        recurse(0, base, base_weight)
    except BudgetExceeded as exc:
        return closed(UNPROVEN, f"search budget exhausted: {exc}; no table released")
    if best_set is None:
        return closed(INFEASIBLE, "no feasible release set exists")

    published_ids = {
        _item_id(item, table): oracle.value_of(item)
        for item in sorted(best_set, key=lambda item: _item_id(item, table))
    }
    suppressed = [
        SuppressedItem(
            _item_id(item, table),
            PRIMARY_SENSITIVE
            if item[0] == "cell" and (item[1], item[2]) in sensitive
            else COMPLEMENTARY_SUPPRESSION,
        )
        for item in cells + marginals
        if item not in best_set
    ]
    constraints = oracle.constraints_for(best_set)
    witnesses: list[CompletionWitness] = []
    for i, j in sorted(sensitive):
        target = i * cols + j
        cell_id = _item_id(("cell", i, j), table)
        for maximize in (False, True):
            solved = oracle.completion(constraints, target, maximize)
            if solved is None:
                return closed(UNPROVEN, "witness reconstruction failed; no table released")
            witnesses.append(
                CompletionWitness(
                    cell=cell_id,
                    value=solved[target],
                    table=tuple(
                        tuple(solved[i * cols + j] for j in range(cols))
                        for i in range(rows)
                    ),
                )
            )
    return ReleaseDecision(
        status=OPTIMAL,
        table=table,
        policy=policy,
        published=tuple(sorted(published_ids.items())),
        suppressed=tuple(sorted(suppressed, key=lambda item: item.item)),
        witnesses=tuple(witnesses),
        released_weight=best_weight,
        available_weight=base_weight + suffix[0],
        release_nodes=budget.release_nodes,
        oracle_nodes=budget.oracle_nodes,
        detail="exact optimum under the declared policy and budget",
    )
