"""Declared-regime decision and exact permutation assembly for audit trends.

Imported lazily by :mod:`drillverify.trend` to keep both modules within the
project's 300-line limit.
"""

from __future__ import annotations

import itertools
import math
from fractions import Fraction
from typing import Any, Sequence

from .trend import (ASSUMPTIONS, CAVEAT, MODES, RunObservation, TrendSpec,
                    _event, _metric_parts)


def statistic(layers, chosen):
    """Weighted within-layer recent-minus-baseline event-rate difference."""
    total = sum(len(layer["runs"]) for layer in layers)
    values = []
    for index in range(len(layers[0]["bits"])):
        value = Fraction(0)
        for layer, recent in zip(layers, chosen):
            n, k, bits = len(layer["runs"]), len(recent), layer["bits"][index]
            hit = sum(1 for i in recent if bits[i])
            all_events = sum(1 for bit in bits if bit)
            value += Fraction(n, total) * (
                Fraction(hit, k) - Fraction(all_events - hit, n - k))
        values.append(value)
    return values


def permutation_counts(layers: Sequence[dict[str, Any]], metrics: int,
                       max_permutations: int) -> dict[str, Any]:
    """Exhaustively permute labels; count statistics at least as extreme.

    Returns ``None`` counts and ``budget_exceeded`` when the exact search space
    is larger than the declared budget, so callers can report "unproven" rather
    than approximate.
    """
    observed = statistic(layers, [layer["recent_index"] for layer in layers])
    total = math.prod(math.comb(len(layer["runs"]), len(layer["recent_index"]))
                      for layer in layers)
    if total > max_permutations:
        return {"observed": observed, "total": total, "at_least": None,
                "at_least_max": None, "budget_exceeded": True, "enumerated": 0}
    at_least = [0] * metrics
    at_least_max = 0
    observed_max = max(observed)
    states = [itertools.combinations(range(len(layer["runs"])), len(layer["recent_index"]))
              for layer in layers]
    for chosen in itertools.product(*states):
        values = statistic(layers, chosen)
        for index, value in enumerate(values):
            at_least[index] += int(value >= observed[index])
        at_least_max += int(max(values) >= observed_max)
    return {"observed": observed, "total": total, "at_least": at_least,
            "at_least_max": at_least_max, "budget_exceeded": False, "enumerated": total}


def _exact(count: int, total: int) -> str:
    """Report the exact count ratio over the declared permutation total."""
    return f"{count}/{total}"


def value(fraction: Fraction) -> dict[str, Any]:
    return {"numerator": fraction.numerator, "denominator": fraction.denominator,
            "decimal": float(fraction)}


def layer_view(layer) -> dict[str, Any]:
    return {"backup_count": layer["exposure"][0], "drill_count": layer["exposure"][1],
            "run_count": len(layer["runs"]), "baseline": layer["baseline_ids"],
            "recent": layer["recent_ids"]}


def _invalid(spec: TrendSpec) -> str | None:
    if spec.mode not in MODES:
        return f"unknown mode: {spec.mode}"
    if not spec.metrics:
        return "no metrics declared"
    if spec.mode == "duty" and len(spec.metrics) != 1:
        return "duty regime requires exactly one pre-selected metric"
    if len(set(spec.metrics)) != len(spec.metrics):
        return "metrics must be declared once"
    for metric in spec.metrics:
        try:
            _metric_parts(metric)
        except ValueError as exc:
            return str(exc)
    baseline, recent = set(spec.baseline_run_ids), set(spec.recent_run_ids)
    if not baseline or not recent:
        return "both baseline and recent run windows must be declared"
    if baseline & recent:
        return "baseline and recent windows must not share a run_id"
    if not 0.0 < spec.alpha < 1.0:
        return "alpha must be between 0 and 1"
    if spec.max_permutations < 1:
        return "max_permutations must be positive"
    return None


def _verdict(reason: str, spec: TrendSpec, **extra: Any) -> dict[str, Any]:
    return {"schema_version": 1, "mode": spec.mode, "status": "unproven", "alert": False,
            "reason": reason, "alpha": spec.alpha,
            "declared": {"metrics": list(spec.metrics),
                         "baseline_run_ids": list(spec.baseline_run_ids),
                         "recent_run_ids": list(spec.recent_run_ids)},
            "assumptions": list(ASSUMPTIONS), "caveat": CAVEAT, **extra}


def _strata(spec: TrendSpec, by_id: dict[str, RunObservation]) -> list[dict[str, Any]]:
    layers: dict[tuple[int, int], dict[str, list[str]]] = {}
    for window, ids in (("baseline", spec.baseline_run_ids), ("recent", spec.recent_run_ids)):
        for run_id in ids:
            if run_id in by_id:
                layers.setdefault(by_id[run_id].exposure,
                                  {"baseline": [], "recent": []})[window].append(run_id)
    return [{"exposure": exposure, "baseline": sorted(layer["baseline"]),
             "recent": sorted(layer["recent"])}
            for exposure, layer in sorted(layers.items())
            if layer["baseline"] and layer["recent"]]


def _layers(spec, strata, by_id):
    layers = []
    for layer in strata:
        ordered = [by_id[run_id] for run_id in layer["baseline"] + layer["recent"]]
        recent = {run_id for run_id in layer["recent"]}
        layers.append({
            "exposure": layer["exposure"], "runs": ordered,
            "bits": [tuple(any(_event(metric, f) for f in item.findings)
                           for item in ordered) for metric in spec.metrics],
            "baseline_ids": layer["baseline"], "recent_ids": layer["recent"],
            "recent_index": tuple(i for i, item in enumerate(ordered)
                                  if item.run_id in recent)})
    return layers


def analyze_observations(observations: Sequence[RunObservation],
                         duplicates: Sequence[dict[str, Any]],
                         spec: TrendSpec) -> dict[str, Any]:
    """Run the declared exact permutation test over de-duplicated observations."""
    invalid = _invalid(spec)
    if invalid:
        return _verdict(invalid, spec, duplicates=list(duplicates))
    by_id = {item.run_id: item for item in observations}
    declared_ids = spec.baseline_run_ids + spec.recent_run_ids
    missing = sorted(set(declared_ids) - set(by_id))
    if missing:
        return _verdict("declared runs missing or conflicting: " + ", ".join(missing),
                        spec, duplicates=list(duplicates),
                        sample={"duplicates": list(duplicates)})
    frames = {(by_id[r].scope, by_id[r].rule_version, by_id[r].window_days)
              for r in declared_ids}
    if len(frames) != 1:
        return _verdict("runs mix plan dataset scope, rule version or window convention",
                        spec, duplicates=list(duplicates))
    scope, version, window_days = frames.pop()
    if not scope or not version or window_days < 1:
        return _verdict("run comparability metadata is unavailable", spec,
                        duplicates=list(duplicates))
    strata = _strata(spec, by_id)
    if not strata:
        return _verdict("no exposure layer contains both baseline and recent runs", spec,
                        sample={key: [r for r in getattr(spec, key) if r in by_id]
                                for key in ("baseline_run_ids", "recent_run_ids")},
                        duplicates=list(duplicates))
    matched = {r for layer in strata for key in ("baseline", "recent") for r in layer[key]}
    layers = _layers(spec, strata, by_id)
    counts = permutation_counts(layers, len(spec.metrics), spec.max_permutations)
    wire = [layer_view(layer) for layer in layers]
    permutation = {"total": counts["total"], "budget": spec.max_permutations,
                   "enumerated": counts["enumerated"],
                   "at_least_observed": counts["at_least_max"],
                   "exhausted": not counts["budget_exceeded"]}
    if counts["budget_exceeded"]:
        return _verdict(
            f"permutation search space {counts['total']} exceeds budget "
            f"{spec.max_permutations}", spec, duplicates=list(duplicates),
            strata=wire, permutation={**permutation, "at_least_observed": None})
    observed, at_least = counts["observed"], counts["at_least"]
    observed_max = max(observed)
    max_metrics = [metric for metric, stat in zip(spec.metrics, observed) if stat == observed_max]
    total = counts["total"]
    decision_count = at_least[0] if spec.mode == "duty" else counts["at_least_max"]
    alert = Fraction(decision_count, total) <= Fraction(str(spec.alpha))
    permutation["at_least_observed"] = (at_least[0] if spec.mode == "duty"
                                        else counts["at_least_max"])
    metrics = []
    for index, metric in enumerate(spec.metrics):
        events = {"baseline": {}, "recent": {}}
        for layer in layers:
            key = f"{layer['exposure'][0]}/{layer['exposure'][1]}"
            for window in ("baseline", "recent"):
                events[window][key] = [
                    r for r in layer[window + "_ids"]
                    if any(_event(metric, f) for f in by_id[r].findings)]
        metrics.append({"metric": metric, "observed_statistic": value(observed[index]),
                        "observed_events": events,
                        "p_value": at_least[index] / total,
                        "p_exact": _exact(at_least[index], total),
                        "at_least_observed": at_least[index],
                        "permutations": counts["total"],
                        "is_family_max": metric in max_metrics})
    return {
        "schema_version": 1, "mode": spec.mode,
        "status": "alert" if alert else "no_alert", "alert": alert,
        "reason": "exact one-sided permutation test within matched exposure strata",
        "alpha": spec.alpha,
        "declared": {"metrics": list(spec.metrics),
                     "baseline_run_ids": list(spec.baseline_run_ids),
                     "recent_run_ids": list(spec.recent_run_ids)},
        "metrics": metrics,
        "family": {"observed_max": value(observed_max), "observed_metrics": max_metrics,
                   "p_value": counts["at_least_max"] / total,
                   "p_exact": _exact(counts["at_least_max"], total),
                   "at_least_observed": counts["at_least_max"],
                   "permutations": counts["total"]},
        "decision": {"regime": spec.mode,
                     "basis": ("single pre-selected metric exact p" if spec.mode == "duty"
                               else "maximum statistic over all declared metrics"),
                     "p_value": decision_count / total,
                     "p_exact": _exact(decision_count, total), "alert": alert},
        "sample": {
            "comparable_run_ids": sorted(matched),
            "baseline_run_ids": sorted(r for layer in strata for r in layer["baseline"]),
            "recent_run_ids": sorted(r for layer in strata for r in layer["recent"]),
            "excluded": [{"run_id": r, "reason": "no matched exposure counterpart"}
                         for r in declared_ids if r not in matched],
            "comparability": {"plan_dataset_scope": scope, "rule_version": version,
                              "analysis_window_days": window_days},
            "duplicates": list(duplicates)},
        "strata": wire,
        "permutation": permutation,
        "assumptions": list(ASSUMPTIONS), "caveat": CAVEAT,
    }
