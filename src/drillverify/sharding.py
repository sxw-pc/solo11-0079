"""Static GF(2) shard-availability proofs for locally synthesized artifacts.
The tool never reconstructs data.  It only proves, deterministically, whether the
coefficient vectors of the *verified* shards span the full k-dimensional source
space over GF(2).  Vector counts and byte totals never substitute for rank.
"""
from __future__ import annotations
from dataclasses import dataclass
MAX_STRIPE_COUNT = 16
def vector_mask(vector: tuple[int, ...]) -> int:
    """Encode a GF(2) coefficient vector as a bit mask (coefficient 0 is the LSB)."""
    return sum(1 << index for index, bit in enumerate(vector) if bit)
def vector_from_mask(mask: int, width: int) -> tuple[int, ...]:
    return tuple(1 if mask & (1 << index) else 0 for index in range(width))
@dataclass(frozen=True)
class RankProof:
    """Outcome of deterministic GF(2) Gaussian elimination over usable shards."""
    rank: int
    k: int
    basis_masks: tuple[int, ...]
    missing_dimensions: tuple[int, ...]
    @property
    def full_rank(self) -> bool:
        return self.rank == self.k
    def basis_vectors(self) -> tuple[tuple[int, ...], ...]:
        return tuple(vector_from_mask(mask, self.k) for mask in self.basis_masks)
    def witness_vectors(self) -> tuple[tuple[int, ...], ...]:
        return tuple(vector_from_mask(1 << dim, self.k) for dim in self.missing_dimensions)
def eliminate(vectors: tuple[tuple[int, ...], ...], k: int) -> RankProof:
    """Gaussian elimination over GF(2), processing vectors in their given order.
    The chosen basis is therefore deterministic; repeated and zero vectors never
    add rank.
    """
    pivot_of: dict[int, int] = {}
    for vector in vectors:
        mask = vector_mask(vector)
        while mask:
            column = (mask & -mask).bit_length() - 1
            if column not in pivot_of:
                pivot_of[column] = mask
                break
            mask ^= pivot_of[column]
    missing = tuple(dim for dim in range(k) if dim not in pivot_of)
    return RankProof(len(pivot_of), k, tuple(sorted(pivot_of.values())), missing)
@dataclass(frozen=True)
class DomainTolerance:
    """Result of removing every shard of one fault domain and re-proving rank."""
    fault_domain: str
    remaining_rank: int
    full_rank: bool
    missing_dimensions: tuple[int, ...]
def domain_removal_proofs(vectors: tuple[tuple[int, ...], ...],
                          domains: tuple[str, ...], k: int) -> tuple[DomainTolerance, ...]:
    """Re-run the rank proof after each fault domain loses all of its shards.
    Shards sharing a fault domain are never treated as independent redundancy.
    """
    return tuple(
        DomainTolerance(domain, proof.rank, proof.full_rank, proof.missing_dimensions)
        for domain in sorted(set(domains))
        for proof in (
            eliminate(tuple(v for v, owner in zip(vectors, domains) if owner != domain), k),
        )
    )
def first_failing_domain(results: tuple[DomainTolerance, ...]) -> DomainTolerance | None:
    """The deterministically first domain whose total loss breaks full rank."""
    return next((result for result in results if not result.full_rank), None)
