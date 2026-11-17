from __future__ import annotations
from drillverify.sharding import (
    domain_removal_proofs,
    eliminate,
    first_failing_domain,
    vector_from_mask,
    vector_mask,
)
def test_mask_round_trip():
    vector = (1, 0, 1)
    assert vector_from_mask(vector_mask(vector), 3) == vector
def test_full_rank_basis_is_deterministic():
    proof = eliminate(((1, 0, 0), (0, 1, 0), (0, 0, 1)), 3)
    assert proof.full_rank and proof.rank == 3
    assert proof.basis_vectors() == ((1, 0, 0), (0, 1, 0), (0, 0, 1))
    assert proof.missing_dimensions == ()
def test_count_three_but_rank_two_gives_missing_dimension_witness():
    # The canonical trap: 100, 010, 110 are three correct shards but span only 2.
    proof = eliminate(((1, 0, 0), (0, 1, 0), (1, 1, 0)), 3)
    assert proof.rank == 2 and not proof.full_rank
    assert proof.missing_dimensions == (2,)
    assert proof.witness_vectors() == ((0, 0, 1),)
def test_repeated_and_zero_vectors_never_add_rank():
    proof = eliminate(((1, 0, 0), (1, 0, 0), (0, 0, 0), (1, 0, 0)), 3)
    assert proof.rank == 1
    assert proof.missing_dimensions == (1, 2)
def test_parity_style_vectors_still_span():
    # 100, 110, 111 is an independent triangular set including a parity vector.
    proof = eliminate(((1, 0, 0), (1, 1, 0), (1, 1, 1)), 3)
    assert proof.full_rank
def test_order_determines_the_chosen_basis_but_not_the_rank():
    first = eliminate(((0, 1, 0), (1, 1, 0), (1, 0, 0)), 2)
    second = eliminate(((1, 1, 0), (0, 1, 0), (1, 0, 0)), 2)
    assert first.rank == second.rank == 2 and first.full_rank
    assert first.basis_masks == second.basis_masks
def test_domain_removal_does_not_count_same_domain_copies_as_independent():
    # zone-b holds two copies of the same vector; removing zone-a leaves rank 2,
    # and the two zone-b copies never help each other.
    vectors = ((1, 0, 0), (0, 1, 0), (0, 1, 0), (0, 0, 1))
    domains = ("zone-a", "zone-b", "zone-b", "zone-c")
    results = domain_removal_proofs(vectors, domains, 3)
    by_domain = {item.fault_domain: item for item in results}
    assert by_domain["zone-a"].remaining_rank == 2
    assert by_domain["zone-b"].remaining_rank == 2
    assert not by_domain["zone-c"].full_rank and by_domain["zone-c"].remaining_rank == 2
    failed = first_failing_domain(results)
    assert failed is not None and failed.fault_domain == "zone-a"
def test_tolerant_layout_survives_every_domain_loss():
    vectors = ((1, 0, 0), (0, 1, 0), (0, 0, 1), (1, 1, 1))
    domains = ("zone-a", "zone-b", "zone-c", "zone-d")
    results = domain_removal_proofs(vectors, domains, 3)
    assert all(item.full_rank for item in results)
    assert first_failing_domain(results) is None
