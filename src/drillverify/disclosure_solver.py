"""Exact integer oracle for small non-negative table completion problems.

Answers "which values can cell X take" under linear sum equations (fixed
cells, row/column/grand totals) plus declared non-negative integer upper
bounds, using sound interval propagation inside exhaustive DFS. Every search
runs under a hard node budget; exceeding it raises BudgetExceeded and voids
the release decision that depended on it.
"""

from __future__ import annotations

from dataclasses import dataclass


class BudgetExceeded(RuntimeError):
    """Raised when an exact search exceeds its declared node budget."""


@dataclass
class SearchBudget:
    """Hard caps on exact-search effort; exceeding either cap voids the release."""

    max_release_nodes: int = 100_000
    max_oracle_nodes: int = 1_000_000
    release_nodes: int = 0
    oracle_nodes: int = 0

    def tick_release(self) -> None:
        self.release_nodes += 1
        if self.release_nodes > self.max_release_nodes:
            raise BudgetExceeded(
                f"release search exceeded {self.max_release_nodes} nodes"
            )

    def tick_oracle(self) -> None:
        self.oracle_nodes += 1
        if self.oracle_nodes > self.max_oracle_nodes:
            raise BudgetExceeded(f"oracle search exceeded {self.max_oracle_nodes} nodes")


def propagate(los: list[int], his: list[int], constraints: list) -> bool:
    """Sound interval propagation; returns False when a constraint is violated."""
    changed = True
    while changed:
        changed = False
        for members, target in constraints:
            lo_sum = 0
            hi_sum = 0
            for var in members:
                lo_sum += los[var]
                hi_sum += his[var]
            if target < lo_sum or target > hi_sum:
                return False
            for var in members:
                lo, hi = los[var], his[var]
                new_lo = target - hi_sum + hi
                if new_lo < lo:
                    new_lo = lo
                new_hi = target - lo_sum + lo
                if new_hi > hi:
                    new_hi = hi
                if new_lo > new_hi:
                    return False
                if new_lo != lo or new_hi != hi:
                    los[var] = new_lo
                    his[var] = new_hi
                    changed = True
    return True


def solve(
    los: list[int],
    his: list[int],
    constraints: list,
    target: int,
    ascending: bool,
    budget: SearchBudget,
) -> tuple[int, ...] | None:
    """Exact DFS; the first leaf in target-value order is the exact optimum."""
    budget.tick_oracle()
    if not propagate(los, his, constraints):
        return None
    var = -1
    if los[target] != his[target]:
        var = target
    else:
        span: int | None = None
        for candidate in range(len(los)):
            gap = his[candidate] - los[candidate]
            if gap > 0 and (span is None or gap < span):
                var, span = candidate, gap
        if var == -1:
            return tuple(los)
    lo, hi = los[var], his[var]
    if var == target and not ascending:
        values = range(hi, lo - 1, -1)
    else:
        values = range(lo, hi + 1)
    for value in values:
        child_lo = list(los)
        child_hi = list(his)
        child_lo[var] = value
        child_hi[var] = value
        solved = solve(child_lo, child_hi, constraints, target, ascending, budget)
        if solved is not None:
            return solved
    return None


class TableOracle:
    """Exact safety oracle over one table shape and declared cell bounds."""

    def __init__(
        self,
        rows: int,
        cols: int,
        values: tuple[tuple[int, ...], ...],
        bounds: tuple[int, ...],
        budget: SearchBudget,
    ) -> None:
        self.rows = rows
        self.cols = cols
        self.values = values
        self.bounds = bounds
        self.budget = budget
        self.row_totals = tuple(sum(row) for row in values)
        self.col_totals = tuple(
            sum(values[i][j] for i in range(rows)) for j in range(cols)
        )
        self._constraints_cache: dict[frozenset, list] = {}
        self._safe_cache: dict[frozenset, bool] = {}

    def members_of(self, item: tuple) -> tuple[int, ...]:
        if item[0] == "cell":
            return (item[1] * self.cols + item[2],)
        if item[0] == "row":
            return tuple(item[1] * self.cols + j for j in range(self.cols))
        if item[0] == "col":
            return tuple(i * self.cols + item[1] for i in range(self.rows))
        return tuple(range(self.rows * self.cols))

    def value_of(self, item: tuple) -> int:
        if item[0] == "cell":
            return self.values[item[1]][item[2]]
        if item[0] == "row":
            return self.row_totals[item[1]]
        if item[0] == "col":
            return self.col_totals[item[1]]
        return sum(self.row_totals)

    def constraints_for(self, published: frozenset) -> list:
        """Sum equations for one published set, with implied ones filtered out."""
        if published not in self._constraints_cache:
            rows, cols = self.rows, self.cols
            rows_fixed = [
                all(("cell", i, j) in published for j in range(cols)) for i in range(rows)
            ]
            cols_fixed = [
                all(("cell", i, j) in published for i in range(rows)) for j in range(cols)
            ]
            all_rows = all(("row", i) in published for i in range(rows))
            all_cols = all(("col", j) in published for j in range(cols))
            constraints = []
            for item in published:
                if item[0] == "row" and rows_fixed[item[1]]:
                    continue  # implied by its published cells
                if item[0] == "col" and cols_fixed[item[1]]:
                    continue
                if item[0] == "grand" and (all_rows or all_cols):
                    continue  # implied by the published marginals
                constraints.append((self.members_of(item), self.value_of(item)))
            self._constraints_cache[published] = constraints
        return self._constraints_cache[published]

    def is_safe(self, published: frozenset, sensitive: frozenset) -> bool:
        """True when every sensitive cell keeps at least two legal completions."""
        if published in self._safe_cache:
            return self._safe_cache[published]
        constraints = self.constraints_for(published)
        los = [0] * len(self.bounds)
        his = list(self.bounds)
        safe = propagate(los, his, constraints)
        if safe:
            pending = []
            for i, j in sorted(sensitive):
                target = i * self.cols + j
                if los[target] == his[target]:
                    safe = False  # pinned by sound propagation alone
                    break
                pending.append(target)
            for target in pending:
                low = solve(list(los), list(his), constraints, target, True, self.budget)
                high = solve(list(los), list(his), constraints, target, False, self.budget)
                if low is None or high is None or low[target] == high[target]:
                    safe = False
                    break
        self._safe_cache[published] = safe
        return safe

    def completion(
        self, constraints: list, target: int, maximize: bool
    ) -> tuple[int, ...] | None:
        """One exact completion attaining the min (or max) feasible target value."""
        los = [0] * len(self.bounds)
        his = list(self.bounds)
        return solve(los, his, constraints, target, not maximize, self.budget)
