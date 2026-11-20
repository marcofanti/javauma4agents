# Independent Phase E3 controls

The reference is `77649287dc883b75ef563c59f96de8613ecf10d0`.
The pinned joint checker (blob `9cc5d5aab537e9640f1c72ce74170bec4d605ec5`)
passed 37/37 against a fresh full Python Compose project. Its cases
cover separate holder terms, approval thresholds, signed verdicts and
enforcement against the configured mandate. The project published no
host ports and was stopped after the run.

[Reference output](phase-e3-evidence/codex-python-controls.txt).


## Java implementation and verification

The unchanged `joint-check` passed 37/37 on an isolated Java Compose project.
It exercised the every-holder and either-holder accounts, independent holder
terms, the signed grant, one-holder refusal, co-owner and organization
boundaries, and leaving the mandate. The checker also exercises outer-token
refusals. The underlying verdict recount is tested directly with valid
holder signatures in `JointVectorsTest`, which also imports the CPython
mandate, digest, fold and weighted tally vectors.

Both owner stores retain mandates and use an atomic first write for each
joint negotiation. The store contract tests cover isolation between holders,
32 concurrent attempts to bind one negotiation to an agreement, and a drift
observation racing with renewed consent. PostgreSQL 17.12 and memory passed
all 122 store-gate tests without skips.

The Java holder retains the recorded answer until the normal negotiation
expiry so a retried tally question can receive the same decision. The answer
is bound to the agreement, resource, tally, mandate and enrolment in which
she gave it. A repeated question cannot re-pend her or transfer approval to
another agreement. Mandate joins also verify that the holder's issuer agrees
with the issuer in the mandate. The tally's open negotiations and issued grant state are
process-local and the holder's consent is in her owner store.

[Java focused joint gate](phase-e3-evidence/codex-java-joint-check.txt).

## Final sign-off

All 23 live gates passed in sequence from a clean reset and rebuild,
including the unchanged 37-assertion joint check and the 122 store tests.
Full Maven verification with mandatory PostgreSQL passed all 260 tests.
The 52 vendored files match their pinned blobs.

[Final clean aggregate](phase-e3-evidence/codex-java-final-aggregate.txt).
[Full Java and PostgreSQL results](phase-e3-evidence/codex-java-maven.txt).
