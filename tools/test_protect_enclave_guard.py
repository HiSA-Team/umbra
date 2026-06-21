"""Self-check for the demand-paging signer guard. Run: python tools/test_protect_enclave_guard.py"""
from protect_enclave import assert_demand_paging_safe

# code-only blob (no cross-block data refs) is allowed in demand-paging mode
assert_demand_paging_safe(demand_paging=True, reloc_count=0)        # must not raise
# mode off: anything allowed
assert_demand_paging_safe(demand_paging=False, reloc_count=5)       # must not raise
# data-ref blob in demand-paging mode is refused
try:
    assert_demand_paging_safe(demand_paging=True, reloc_count=5)
    raise AssertionError("expected SystemExit for reloc_count>0 in demand-paging mode")
except SystemExit as e:
    assert "demand-paging" in str(e).lower()

print("OK: demand-paging guard self-check passed")
