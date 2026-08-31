# Deprecated: not part of the verified artifact

This directory is retained only to document an abandoned proof attempt. Its
T1–T4 statements are over a hand-written `list N` model rather than Aeneas-
extracted firmware, and `Rot_Chain.v` assumes global injectivity of a fixed-
output MAC. That premise is unsatisfiable by pigeonhole, so the resulting
theorems are vacuous.

Nothing under `rot-core/` supports a claim in the DATE submission. The artifact
build and all reported assumption audits intentionally exclude it. The
replacement is `../chain-core/`: it proves a collision reduction over the
extracted `umbra-chain-core` body without assuming injectivity.

Do not extend or cite these proofs. They are preserved as a negative example of
the failure mode discussed in the paper.
